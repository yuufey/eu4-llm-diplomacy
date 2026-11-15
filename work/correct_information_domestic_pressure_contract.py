"""Withdraw the province-only unity component from the pending N04 profile.

Preserve the initial profile and contract. The new contract supports three
scalars and explicitly records why the fourth mapping was not sufficient.
No process, REA query, or disassembly is performed by this join.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.freeze_information_country_powers import (
    read_json_bounded, dependency_record, _write_json_new, relpath,
)

STAGE = ROOT / "work/runtime/information-domestic-pressure-20261025-001"
PROFILE = ROOT / "bridge/information/profiles/domestic-pressure-memory-1374.json"
OLD_SHA = "38aca9702b4c8d8cf90214a434b4259edb77257901542114864aa2d55fcc256b"
FIELDS = ("stability", "war_exhaustion", "corruption")


def main():
    profile, _, digest = read_json_bounded(PROFILE)
    if digest != OLD_SHA:
        raise ValueError("initial_profile_identity_changed")
    historical = STAGE / "pre-effective-unity-correction-001" / PROFILE.name
    old_contract_path = STAGE / "native-domestic-pressure-contract-001.json"
    old_contract, _, old_contract_sha = read_json_bounded(old_contract_path)
    evidence_path = STAGE / "rea-religious-unity-ratio-001/evidence.json"
    evidence, _, _ = read_json_bounded(evidence_path)
    if evidence["subject"]["digest"]["sha256"] != profile["executable"]["sha256"]:
        raise ValueError("getter_executable_mismatch")
    value = evidence["raw_result"]["value"]
    if value["procedure"]["address"] != "0x1403b4530":
        raise ValueError("getter_procedure_mismatch")
    anchors = (
        "iVar7 = *(int *)(param_1 + 0xee0);",
        '"RELIG_UNITY_FROM_PROVINCES"',
        "if (*piVar5 == 0xa8)",
        "plVar2 = *(longlong **)(DAT_142358060 + 0x3f40);",
        "iVar7 = iVar7 + local_114;", "*param_2 = 1000;",
    )
    if any(anchor not in value["pseudocode"] for anchor in anchors):
        raise ValueError("effective_unity_semantic_anchor_missing")
    historical.parent.mkdir(parents=True, exist_ok=True)
    with historical.open("xb") as stream:
        stream.write(PROFILE.read_bytes())
    contract_path = STAGE / "native-domestic-pressure-contract-002.json"
    contract = {
        "schema": "information_native_domestic_pressure_contract_v2",
        "contract_id": "native-domestic-pressure-contract-002",
        "evidence_kind": "REA_semantics_plus_bounded_PE_records_not_runtime",
        "game": old_contract["game"],
        "fields": {field: old_contract["fields"][field] for field in FIELDS},
        "rea_records": old_contract["rea_records"],
        "compiled_token_records": {field: old_contract["compiled_token_records"][field] for field in FIELDS},
        "supersedes": {"path": relpath(old_contract_path), "sha256": old_contract_sha,
                       "scope": "initial religious_unity mapping withdrawn; the other three storage mappings are retained"},
        "semantic_join": [text for text in old_contract["semantic_join"] if not text.startswith("religious_unity")],
        "excluded_fields": {
            "religious_unity": {
                "status": "not_implemented", "country_offset_0xee0": "province_component_only",
                "evidence": dependency_record(evidence_path, role="REA effective-unity exclusion"),
                "evidence_id": evidence["evidence_id"],
                "body_static_va": value["procedure"]["body"]["ranges"],
                "pseudocode_anchors": list(anchors),
                "reason": "The native getter labels EE0 as RELIG_UNITY_FROM_PROVINCES, adds modifier0xa8 with a possible callback, handles a special rule and can clamp to1000. Reading the saved component does not give final current religious unity.",
            },
            "overextension": {"status": "not_implemented"},
            "unrest": {"status": "not_implemented"},
        },
        "unknown_conditions": old_contract["unknown_conditions"] + [
            "Final current religious unity requires the complete modifier/callback/special-rule path; it remains planned.",
            "The three retained scalars still require fresh native runtime and MCP acceptance.",
        ],
    }
    _, contract_sha = _write_json_new(contract_path, contract, overwrite=False)
    corrected = deepcopy(profile)
    corrected["profile_version"] = 2
    corrected["contract_sha256"] = contract_sha
    corrected["scalars"] = {field: profile["scalars"][field] for field in FIELDS}
    corrected["save_tokens"]["tokens"] = {field: profile["save_tokens"]["tokens"][field] for field in FIELDS}
    corrected["provenance"]["contract_path"] = relpath(contract_path)
    corrected["provenance"]["contract_sha256"] = contract_sha
    dependencies = [item for item in profile["provenance"]["dependencies"] if item["path"] != relpath(old_contract_path)]
    dependencies.extend((dependency_record(contract_path, role="corrected three-scalar contract"),
                         dependency_record(evidence_path, role="REA exclusion of province-only unity component"),
                         dependency_record(Path(__file__), role="reviewable semantic correction builder")))
    corrected["provenance"]["dependencies"] = dependencies
    corrected["unknown_conditions"] = contract["unknown_conditions"]
    corrected["excluded_fields"] = {"religious_unity": "EE0_is_province_component_not_effective_unity"}
    raw = (json.dumps(corrected, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(raw) > 64 * 1024:
        raise ValueError("corrected_profile_exceeds_reader_bound")
    # The exact previous profile is retained above before updating the active
    # checked-in profile; immutable contract/evidence files are not changed.
    PROFILE.write_bytes(raw)
    report = {
        "status": "corrected_pending_runtime", "runtime_observation": False,
        "previous_profile": dependency_record(historical, role="superseded four-field profile"),
        "profile": dependency_record(PROFILE, role="current three-field profile"),
        "contract": dependency_record(contract_path, role="corrected semantic contract"),
        "removed_mapping": "religious_unity_from_country_EE0",
        "code_guards_unchanged": corrected["code_guards"] == profile["code_guards"],
        "remaining_fields": list(FIELDS), "real_native_capture_available": False,
    }
    _write_json_new(STAGE / "effective-unity-correction-001.json", report, overwrite=False)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
