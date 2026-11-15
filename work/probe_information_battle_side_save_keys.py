"""Inventory compiled save-key records referenced by the battle-side writer.

This is a bounded, read-only static join.  It checks the completed REA report
for ``FUN_1401dce20`` and reads the requested records from the fixed 1.37.4
PE initializer table.  The records are compiled defaults only: this script
does not read the runtime key vector and assigns no battle-field type, width,
unit, scale, or side semantics.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.probe_information_battle_save_keys import (  # noqa: E402
    DEFAULT_EXE,
    EXPECTED_EXE_SHA256,
    IMAGE_BASE,
    _hex_int,
    _procedure_reference,
    _read_pe_rva_bounded,
    _require,
    read_json_bounded,
    relpath,
    sha256_bytes,
    sha256_file,
)


STAGE = ROOT / "work/runtime/information-battle-layout-20261025-001"
SIDE_EVIDENCE = STAGE / "rea-side-writer-001/evidence.json"
PROFILE = ROOT / "bridge/information/profiles/domestic-pressure-memory-1374.json"
CONTRACT = ROOT / "work/runtime/information-domestic-pressure-20261025-001/native-domestic-pressure-contract-003.json"
OUTPUT = STAGE / "side-save-keys-001.json"

SIDE_WRITER_RVA = 0x1DCE20
EXPECTED_PROVIDER_VERSION = "12.1.4"

# Keep this order identical to the new writer query.  The order is evidence
# metadata, not an inferred ordering of save fields.
REQUESTED_SIDE_KEY_IDS: tuple[int, ...] = (
    0x2780,
    0x2787,
    0x2785,
    0x2784,
    0x2782,
    0x2781,
    0x2786,
    0x28FC,
    0x289D,
    0x2DE6,
    0x2D62,
)


def _side_writer_reference() -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    """Validate the completed side-writer report and retain its static joins."""
    evidence, size, digest = read_json_bounded(SIDE_EVIDENCE)
    reference = _procedure_reference(SIDE_EVIDENCE, SIDE_WRITER_RVA, "battle-side-save-key-writer")
    pseudo = evidence.get("raw_result", {}).get("value", {}).get("pseudocode")
    _require(isinstance(pseudo, str), "side_writer_pseudocode_missing")
    anchors = (
        "FUN_141707b30(param_2,0x2780);",
        "FUN_141707b30(param_2,0x2787);",
        "FUN_141707b30(param_2,0x2785);",
        "FUN_141707b30(param_2,0x2784);",
        "FUN_141707b30(param_2,0x2782);",
        "FUN_141707b30(param_2,0x2781);",
        "FUN_141707b30(param_2,0x2786);",
        "FUN_1417091b0(param_2,0x28fc);",
        "FUN_1417091b0(param_2,0x289d);",
        "FUN_141707b30(param_2,0x2de6);",
        "FUN_1417091b0(param_2,0x2d62);",
    )
    anchor_checks = {anchor: anchor in pseudo for anchor in anchors}
    _require(all(anchor_checks.values()), f"side_writer_key_anchor_missing:{anchor_checks}")

    request_path = SIDE_EVIDENCE.with_name("request.json")
    run_path = SIDE_EVIDENCE.with_name("run.json")
    request, request_size, request_sha = read_json_bounded(request_path, max_bytes=64 * 1024)
    request_checks = {
        "target_sha256": request.get("target_sha256") == EXPECTED_EXE_SHA256,
        "node": request.get("node") == hex(SIDE_WRITER_RVA),
        "procedure": request.get("procedure") == hex(IMAGE_BASE + SIDE_WRITER_RVA),
        "preset": request.get("preset") == "eu4-persistent-default-analysis-v1",
        "adapter_sha256": request.get("adapter_sha256") == "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d",
        "manifest_sha256": request.get("completed_manifest_sha256") == "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a",
        "database_sha256": request.get("completed_database_sha256") == "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161",
        "query_reanalysis": request.get("query_reanalysis") is False,
        "java_heap": request.get("java_heap") == "512M",
        "process_memory_limit_bytes": request.get("process_memory_limit_bytes") == 1024**3,
    }
    _require(all(request_checks.values()), f"side_writer_request_guard_failed:{request_checks}")

    run, run_size, run_sha = read_json_bounded(run_path, max_bytes=64 * 1024)
    run_checks = {
        "target_sha256": run.get("target_sha256") == EXPECTED_EXE_SHA256,
        "node": run.get("node") == hex(SIDE_WRITER_RVA),
        "procedure": run.get("procedure") == hex(IMAGE_BASE + SIDE_WRITER_RVA),
        "exit_code": run.get("exit_code") == 0,
        "reason": run.get("reason") == "completed",
        "database_unchanged": run.get("database_unchanged") is True,
        "evidence_id": run.get("evidence_id") == evidence.get("evidence_id"),
    }
    _require(all(run_checks.values()), f"side_writer_run_guard_failed:{run_checks}")
    processes = run.get("processes")
    _require(isinstance(processes, list) and processes, "side_writer_processes_missing")
    peaks = [
        item.get("peak_committed_bytes")
        for item in processes
        if isinstance(item, Mapping)
    ]
    _require(
        peaks
        and all(isinstance(value, int) and not isinstance(value, bool) and value < 1024**3 for value in peaks),
        "side_writer_peak_guard_failed",
    )
    _require(
        all(item.get("still_running_same_process") is False for item in processes if isinstance(item, Mapping)),
        "side_writer_process_not_closed",
    )

    reference.update(
        {
            "request": {
                "path": relpath(request_path),
                "bytes": request_size,
                "sha256": request_sha,
                "checks": request_checks,
            },
            "run": {
                "path": relpath(run_path),
                "bytes": run_size,
                "sha256": run_sha,
                "checks": run_checks,
                "peak_committed_bytes": max(peaks),
            },
            "anchor_checks": anchor_checks,
        }
    )

    associations = [
        {
            "key_id": 0x2780,
            "key_id_hex": "0x2780",
            "source_offsets": ["0x3c"],
            "source_expression": "*(int *)(param_1 + 0x3c)",
            "condition": "0 < *(int *)(param_1 + 0x3c)",
            "write_call": "FUN_141707b30(param_2,0x2780)",
            "condition_kind": "decompiler_signed_comparison; width_and_scale_unresolved",
        },
        {
            "key_id": 0x2787,
            "key_id_hex": "0x2787",
            "source_offsets": ["0x4c"],
            "source_expression": "*(int *)(param_1 + 0x4c)",
            "condition": "0 < *(int *)(param_1 + 0x4c)",
            "write_call": "FUN_141707b30(param_2,0x2787)",
            "condition_kind": "decompiler_signed_comparison; width_and_scale_unresolved",
        },
        {
            "key_id": 0x2785,
            "key_id_hex": "0x2785",
            "source_offsets": ["0x48"],
            "source_expression": "*(int *)(param_1 + 0x48)",
            "condition": "0 < *(int *)(param_1 + 0x48)",
            "write_call": "FUN_141707b30(param_2,0x2785)",
            "condition_kind": "decompiler_signed_comparison; width_and_scale_unresolved",
        },
        {
            "key_id": 0x2784,
            "key_id_hex": "0x2784",
            "source_offsets": ["0x44"],
            "source_expression": "*(int *)(param_1 + 0x44)",
            "condition": "0 < *(int *)(param_1 + 0x44)",
            "write_call": "FUN_141707b30(param_2,0x2784)",
            "condition_kind": "decompiler_signed_comparison; width_and_scale_unresolved",
        },
        {
            "key_id": 0x2782,
            "key_id_hex": "0x2782",
            "source_offsets": ["0x40"],
            "source_expression": "*(int *)(param_1 + 0x40)",
            "condition": "0 < *(int *)(param_1 + 0x40)",
            "write_call": "FUN_141707b30(param_2,0x2782)",
            "condition_kind": "decompiler_signed_comparison; width_and_scale_unresolved",
        },
        {
            "key_id": 0x2781,
            "key_id_hex": "0x2781",
            "source_offsets": ["0x38"],
            "source_expression": "*(int *)(param_1 + 0x38)",
            "condition": "0 < *(int *)(param_1 + 0x38)",
            "write_call": "FUN_141707b30(param_2,0x2781)",
            "condition_kind": "decompiler_signed_comparison; width_and_scale_unresolved",
        },
        {
            "key_id": 0x2786,
            "key_id_hex": "0x2786",
            "source_offsets": ["0x50"],
            "source_expression": "*(int *)(param_1 + 0x50)",
            "condition": "0 < *(int *)(param_1 + 0x50)",
            "write_call": "FUN_141707b30(param_2,0x2786)",
            "condition_kind": "decompiler_signed_comparison; width_and_scale_unresolved",
        },
        {
            "key_id": 0x28FC,
            "key_id_hex": "0x28fc",
            "source_offsets": ["0x54"],
            "source_expression": "*(undefined4 *)(param_1 + 0x54) -> uVar1 -> FUN_14015c260(...,uVar1)",
            "condition": "unconditional in observed writer body",
            "write_call": "FUN_1417091b0(param_2,0x28fc)",
            "condition_kind": "formatted_value_source; decompiler type only; width_and_scale_unresolved",
        },
        {
            "key_id": 0x289D,
            "key_id_hex": "0x289d",
            "source_offsets": ["0x10"],
            "source_expression": "NUL scan from param_1 + 0x10 into local string buffer",
            "condition": "unconditional key write after observed string preparation",
            "write_call": "FUN_1417091b0(param_2,0x289d) then FUN_141707cc0(...)",
            "condition_kind": "NUL_terminated_string_source; width_and_scale_unresolved",
        },
        {
            "key_id": 0x2DE6,
            "key_id_hex": "0x2de6",
            "source_offsets": ["0x74"],
            "source_expression": "*(int *)(param_1 + 0x74)",
            "condition": "*(int *)(param_1 + 0x74) != 0",
            "write_call": "FUN_141707b30(param_2,0x2de6)",
            "condition_kind": "decompiler_nonzero_comparison; width_and_scale_unresolved",
        },
        {
            "key_id": 0x2D62,
            "key_id_hex": "0x2d62",
            "source_offsets": ["0x18", "0x30"],
            "source_expression": "string source at param_1 + 0x18; indirection selected by *(ulonglong *)(param_1 + 0x30)",
            "condition": "unconditional key write; heap/inline branch when 0xf < *(ulonglong *)(param_1 + 0x30)",
            "write_call": "FUN_1417091b0(param_2,0x2d62) then FUN_141707cc0(...)",
            "condition_kind": "string_storage_branch; width_and_scale_unresolved",
        },
    ]
    return reference, pseudo, associations


def _compiled_side_records(profile: Mapping[str, Any], contract: Mapping[str, Any], exe: Path) -> dict[str, Any]:
    token_records = contract.get("compiled_token_records")
    _require(isinstance(token_records, Mapping) and token_records, "compiled_token_records_missing")
    layouts = {
        (tuple(item.get("record_array_rva", [])), item.get("stride"))
        for item in token_records.values()
        if isinstance(item, Mapping)
    }
    _require(len(layouts) == 1, f"record_layouts_disagree:{layouts}")
    (record_array, stride), = layouts
    _require(len(record_array) == 2 and stride == 0x208, "record_array_layout_unexpected")
    array_start = _hex_int(record_array[0], "record_array.start")
    array_end = _hex_int(record_array[1], "record_array.end")
    _require(array_end > array_start and (array_end - array_start) % stride == 0, "record_array_bounds_invalid")
    total_bytes, exe_sha = sha256_file(exe)
    _require(exe_sha == EXPECTED_EXE_SHA256, "fixed_executable_sha256_mismatch")
    table = _read_pe_rva_bounded(exe, array_start, array_end - array_start)
    _require(len(table) == array_end - array_start, "record_table_read_size_mismatch")

    matches: dict[int, list[dict[str, Any]]] = {key_id: [] for key_id in REQUESTED_SIDE_KEY_IDS}
    slot_count = (array_end - array_start) // stride
    for index in range(slot_count):
        slot_rva = array_start + index * stride
        slot = table[index * stride : (index + 1) * stride]
        key_id = int.from_bytes(slot[:4], "little", signed=False)
        if key_id not in matches:
            continue
        tail = slot[4:]
        name_end = tail.find(b"\0")
        _require(name_end >= 0, f"record_name_not_terminated:{hex(key_id)}")
        try:
            name = tail[:name_end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError(f"record_name_not_ascii:{hex(key_id)}") from exc
        raw_prefix = slot[: 4 + name_end + 1]
        matches[key_id].append(
            {
                "key_id": key_id,
                "key_id_hex": hex(key_id),
                "compiled_name": name,
                "record_index": index,
                "record_rva": hex(slot_rva),
                "record_va": hex(IMAGE_BASE + slot_rva),
                "record_array_rva_start": hex(array_start),
                "record_array_rva_end_exclusive": hex(array_end),
                "record_stride": stride,
                "raw_bytes_hex": raw_prefix.hex(),
                "raw_bytes_length": len(raw_prefix),
                "raw_bytes_sha256": sha256_bytes(raw_prefix),
                "slot_bytes": len(slot),
                "slot_sha256": sha256_bytes(slot),
                "source": "fixed_executable_compiled_initializer_record",
                "runtime_key_vector_override": "unknown_not_read",
                "semantic_status": "compiled_name_observed_field_semantics_unresolved",
            }
        )

    records: list[dict[str, Any]] = []
    for key_id in REQUESTED_SIDE_KEY_IDS:
        values = matches[key_id]
        _require(len(values) == 1, f"record_key_not_unique:{hex(key_id)}:{len(values)}")
        records.append(values[0])
    return {
        "fixed_executable": {
            "path": relpath(exe),
            "bytes": total_bytes,
            "sha256": exe_sha,
            "image_base": hex(IMAGE_BASE),
            "game_version": "1.37.4",
        },
        "record_layout": {
            "array_rva_start": hex(array_start),
            "array_rva_end_exclusive": hex(array_end),
            "stride": stride,
            "slot_count": slot_count,
            "record_bytes_read_per_slot": stride,
            "array_end_semantics": "exclusive",
        },
        "records": records,
    }


def build() -> dict[str, Any]:
    if OUTPUT.exists():
        raise FileExistsError(f"refusing_to_overwrite:{OUTPUT}")
    _require(DEFAULT_EXE.is_file(), f"fixed_executable_missing:{DEFAULT_EXE}")
    writer_ref, writer_pseudo, associations = _side_writer_reference()
    profile, profile_size, profile_sha = read_json_bounded(PROFILE, max_bytes=128 * 1024)
    contract, contract_size, contract_sha = read_json_bounded(CONTRACT, max_bytes=128 * 1024)
    _require(profile.get("profile_id") == "domestic-pressure-memory-1374", "profile_id_unexpected")
    _require(profile.get("executable", {}).get("sha256") == EXPECTED_EXE_SHA256, "profile_exe_sha_mismatch")
    _require(profile.get("save_tokens", {}).get("vector_rva") == "0x242b868", "profile_vector_rva_unexpected")
    _require(contract.get("contract_id") == "native-domestic-pressure-contract-003", "contract_id_unexpected")

    initializer_ref = _procedure_reference(
        ROOT / profile["source_evidence"]["compiled_save_token_initializer"]["path"],
        0x170D180,
        "legacy_compiled_save_token_initializer_layout",
    )
    resolver_ref = _procedure_reference(
        ROOT / profile["source_evidence"]["save_key_resolver"]["path"],
        0x17091B0,
        "legacy_runtime_save_key_resolver",
    )
    vector_ref = _procedure_reference(
        ROOT / profile["source_evidence"]["save_key_vector"]["path"],
        0x170D980,
        "legacy_runtime_save_key_vector_builder",
    )
    records = _compiled_side_records(profile, contract, DEFAULT_EXE)

    return {
        "schema": "information_battle_side_save_key_inventory_v1",
        "status": "static_compiled_records_observed_runtime_override_unresolved",
        "scope": {
            "read_only": True,
            "game_version": "1.37.4",
            "target_executable_sha256": EXPECTED_EXE_SHA256,
            "native_function_invoked": False,
            "game_or_rpm_access": False,
            "semantic_field_mapping": False,
            "goal_complete": False,
        },
        "writer": {
            **writer_ref,
            "selected_key_ids": [hex(key_id) for key_id in REQUESTED_SIDE_KEY_IDS],
            "static_source_associations": associations,
            "pseudocode_sha256_utf8": sha256_bytes(writer_pseudo.encode("utf-8")),
            "interpretation": "writer literals, offsets, and conditions are static expressions only; they do not establish field type, width, unit, scale, side, or battle-result semantics",
        },
        "compiled_record_inventory": records,
        "legacy_layout_evidence": {
            "profile": {
                "path": relpath(PROFILE),
                "bytes": profile_size,
                "sha256": profile_sha,
                "profile_id": profile.get("profile_id"),
            },
            "contract": {
                "path": relpath(CONTRACT),
                "bytes": contract_size,
                "sha256": contract_sha,
                "contract_id": contract.get("contract_id"),
            },
            "initializer": initializer_ref,
            "resolver": resolver_ref,
            "vector_builder": vector_ref,
            "layout_source": "contract compiled_token_records.record_array_rva/stride, cross-checked against profile source evidence",
        },
        "runtime_key_vector_boundary": {
            "vector_rva": profile["save_tokens"]["vector_rva"],
            "vector_source": "profile save_tokens.vector_rva",
            "runtime_registration_or_override": "not_read",
            "static_compiled_records_are_defaults_only": True,
            "actual_runtime_names_and_key_addresses": "unknown",
            "no_semantic_inference_from_id_or_name": True,
        },
        "limitations": [
            "Compiled names are fixed-executable initializer records, not proof of current runtime key-vector membership.",
            "The side writer has conditional sources, a formatted source, and string sources; this inventory records only observed literals, offsets, and conditions.",
            "No requested ID is assigned a unit type, width, sign, scale, side, or battle-result meaning.",
            "Initializer, resolver, vector, and side-writer Evidence IDs are static references and do not authorize a runtime call or dispatch.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    value = build()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    OUTPUT.write_bytes(raw)
    print(
        json.dumps(
            {"status": "passed", "path": relpath(OUTPUT), "bytes": len(raw), "sha256": sha256_bytes(raw)},
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
