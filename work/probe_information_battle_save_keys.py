"""Inventory compiled save-key records referenced by the battle result writer.

This is a bounded, read-only static join.  It reads the already completed
``0x1dd240`` REA report, the fixed-build PE record table, and the existing N04
initializer/resolver/vector evidence.  It does not run REA, open a process,
invoke a game/native function, or read the runtime key vector.

The record names below are observations from the fixed executable's compiled
initializer table.  They are not field semantics: the game's runtime key
vector can register or override entries, and that runtime condition is not
observed by this script.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.freeze_information_country_powers import (  # noqa: E402
    DEFAULT_EXE,
    EXPECTED_EXE_SHA256,
    IMAGE_BASE,
    _read_pe_rva_bytes,
    read_json_bounded,
    relpath,
    sha256_bytes,
    sha256_file,
)


STAGE = ROOT / "work/runtime/information-battle-layout-20261025-001"
WRITER_EVIDENCE = STAGE / "rea-result-member-002-001/evidence.json"
PROFILE = ROOT / "bridge/information/profiles/domestic-pressure-memory-1374.json"
CONTRACT = ROOT / "work/runtime/information-domestic-pressure-20261025-001/native-domestic-pressure-contract-003.json"
OUTPUT = STAGE / "result-save-keys-001.json"

WRITER_RVA = 0x1DD240
EXPECTED_PROVIDER_VERSION = "12.1.4"
EXPECTED_ADAPTER_SHA256 = "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d"
EXPECTED_MANIFEST_SHA256 = "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a"
EXPECTED_DATABASE_SHA256 = "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161"

# These IDs are the literals selected by the already completed 0x1dd240
# writer query.  They are an input contract for this inventory, not inferred
# from names or from the battle result object.
REQUESTED_KEY_IDS: tuple[int, ...] = (
    0x1B,
    0x2870,
    0x28FB,
    0x284C,
    0x284B,
    0x28F9,
    0x28FA,
    0x30A5,
    0x30A6,
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _hex_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"boolean_not_integer:{label}")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        result = int(value, 0)
    else:
        raise ValueError(f"invalid_integer:{label}")
    if result < 0:
        raise ValueError(f"negative_integer:{label}")
    return result


def _read_pe_rva_bounded(path: Path, rva: int, size: int, *, chunk_bytes: int = 64 * 1024) -> bytes:
    """Read a PE table in the existing helper's bounded slices."""
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        length = min(chunk_bytes, size - offset)
        chunks.append(_read_pe_rva_bytes(path, rva + offset, length))
        offset += length
    return b"".join(chunks)


def _procedure_reference(path: Path, expected_rva: int, role: str) -> dict[str, Any]:
    evidence, size, digest = read_json_bounded(path)
    _require(evidence.get("evidence_id", "").startswith("ev_"), f"{path}_evidence_id_missing")
    _require(
        evidence.get("subject", {}).get("digest", {}).get("sha256") == EXPECTED_EXE_SHA256,
        f"{path}_exe_sha_mismatch",
    )
    provider = evidence.get("provider", {})
    _require(provider.get("version") == EXPECTED_PROVIDER_VERSION, f"{path}_provider_version_mismatch")
    profile = evidence.get("analysis_profile", {}).get("parameters", {})
    profile_checks = {
        "analyzer_preset": profile.get("analyzer_preset") == "eu4-persistent-default-analysis-v1",
        "adapter_sha256": profile.get("local_adapter_sha256") == EXPECTED_ADAPTER_SHA256,
        "manifest_sha256": profile.get("completed_manifest_sha256") == EXPECTED_MANIFEST_SHA256,
        "database_sha256": profile.get("completed_database_sha256") == EXPECTED_DATABASE_SHA256,
        "query_reanalysis": profile.get("query_reanalysis") is False,
    }
    _require(all(profile_checks.values()), f"{path}_profile_guard_failed:{profile_checks}")
    value = evidence.get("raw_result", {}).get("value", {})
    procedure = value.get("procedure", {})
    address = _hex_int(procedure.get("address"), f"{path}.procedure.address")
    _require(address - IMAGE_BASE == expected_rva, f"{path}_procedure_rva_mismatch")
    body = procedure.get("body", {})
    ranges = body.get("ranges")
    _require(isinstance(ranges, list) and ranges, f"{path}_body_ranges_missing")
    body_ranges: list[dict[str, Any]] = []
    parsed: list[tuple[int, int]] = []
    for item in ranges:
        start = _hex_int(item.get("start"), f"{path}.body.start")
        end = _hex_int(item.get("end"), f"{path}.body.end")
        _require(end >= start and start >= IMAGE_BASE, f"{path}_body_range_invalid")
        parsed.append((start, end))
        body_ranges.append(
            {
                "va_start": hex(start),
                "va_end_inclusive": hex(end),
                "va_end_exclusive": hex(end + 1),
                "rva_start": hex(start - IMAGE_BASE),
                "rva_end_inclusive": hex(end - IMAGE_BASE),
                "rva_end_exclusive": hex(end - IMAGE_BASE + 1),
            }
        )
    total = sum(end - start + 1 for start, end in parsed)
    span = max(end for _, end in parsed) - min(start for start, _ in parsed) + 1
    _require(body.get("total_bytes") == total and body.get("span_bytes") == span, f"{path}_body_size_mismatch")
    pseudo = value.get("pseudocode")
    _require(isinstance(pseudo, str), f"{path}_pseudocode_missing")
    return {
        "role": role,
        "path": relpath(path),
        "bytes": size,
        "sha256": digest,
        "evidence_id": evidence["evidence_id"],
        "procedure": {
            "name": procedure.get("name"),
            "va": hex(address),
            "rva": hex(address - IMAGE_BASE),
        },
        "body": {
            "range_count": len(body_ranges),
            "total_bytes": total,
            "span_bytes": span,
            "end_semantics": "REA procedure.body.ranges end is inclusive",
            "ranges": body_ranges,
        },
        "pseudocode": {
            "chars": len(pseudo),
            "sha256_utf8": sha256_bytes(pseudo.encode("utf-8")),
        },
        "profile_checks": profile_checks,
    }


def _writer_reference() -> tuple[dict[str, Any], str, dict[str, Any]]:
    evidence, size, digest = read_json_bounded(WRITER_EVIDENCE)
    ref = _procedure_reference(WRITER_EVIDENCE, WRITER_RVA, "result-vtable-save-key-writer")
    pseudo = evidence["raw_result"]["value"]["pseudocode"]
    anchors = (
        "FUN_1417091b0(param_2,0x1b);",
        "FUN_1417091b0(param_2,0x2870);",
        "FUN_1417091b0(param_2,0x28fb);",
        "FUN_1400cf3d0(param_2,0x284c - (uint)(cVar1 != '\\0'));",
        "FUN_1417091b0(param_2,0x28f9);",
        "FUN_1417091b0(param_2,0x28fa);",
        "FUN_1417091b0(param_2,0x30a5);",
        "FUN_1417091b0(param_2,0x30a6);",
    )
    _require(all(anchor in pseudo for anchor in anchors), "writer_key_anchor_missing")
    run_path = WRITER_EVIDENCE.with_name("run.json")
    request_path = WRITER_EVIDENCE.with_name("request.json")
    request, request_size, request_sha = read_json_bounded(request_path, max_bytes=64 * 1024)
    request_checks = {
        "target_sha256": request.get("target_sha256") == EXPECTED_EXE_SHA256,
        "node": request.get("node") == hex(WRITER_RVA),
        "procedure": request.get("procedure") == hex(IMAGE_BASE + WRITER_RVA),
        "preset": request.get("preset") == "eu4-persistent-default-analysis-v1",
        "adapter_sha256": request.get("adapter_sha256") == EXPECTED_ADAPTER_SHA256,
        "manifest_sha256": request.get("completed_manifest_sha256") == EXPECTED_MANIFEST_SHA256,
        "database_sha256": request.get("completed_database_sha256") == EXPECTED_DATABASE_SHA256,
        "query_reanalysis": request.get("query_reanalysis") is False,
    }
    _require(all(request_checks.values()), f"writer_request_guard_failed:{request_checks}")
    run, run_size, run_sha = read_json_bounded(run_path, max_bytes=64 * 1024)
    run_checks = {
        "exit_code": run.get("exit_code") == 0,
        "reason": run.get("reason") == "completed",
        "database_unchanged": run.get("database_unchanged") is True,
        "evidence_id": run.get("evidence_id") == evidence.get("evidence_id"),
    }
    _require(all(run_checks.values()), f"writer_run_guard_failed:{run_checks}")
    peaks = [p.get("peak_committed_bytes") for p in run.get("processes", []) if isinstance(p, Mapping)]
    _require(peaks and all(isinstance(x, int) and not isinstance(x, bool) and x < 1024**3 for x in peaks), "writer_peak_guard_failed")
    _require(all(p.get("still_running_same_process") is False for p in run.get("processes", []) if isinstance(p, Mapping)), "writer_process_not_closed")
    ref["request"] = {"path": relpath(request_path), "bytes": request_size, "sha256": request_sha, "checks": request_checks}
    ref["run"] = {
        "path": relpath(run_path),
        "bytes": run_size,
        "sha256": run_sha,
        "checks": run_checks,
        "peak_committed_bytes": max(peaks),
    }
    associations = {
        "1b": {"key_id": 0x1B, "source_offsets": ["0x118"], "expression": "param_1 + 0x118 -> FUN_141707cc0; key 0x1b"},
        "2870": {"key_id": 0x2870, "source_offsets": [], "expression": "*(int *)(*(longlong *)(param_1 + 0x110) + 0x20) -> key 0x2870"},
        "28fb": {"key_id": 0x28FB, "source_offsets": ["0x108"], "expression": "key 0x28fb -> 0x284c - (uint)(cVar1 != '\\0')"},
        "284c": {"key_id": 0x284C, "source_offsets": [], "expression": "conditional source key selected by 0x28fb: 0x284c"},
        "284b": {"key_id": 0x284B, "source_offsets": [], "expression": "conditional source key selected by 0x28fb: 0x284b"},
        "28f9": {"key_id": 0x28F9, "source_offsets": ["0x10"], "expression": "vtable call on param_1 + 0x10 -> key 0x28f9"},
        "28fa": {"key_id": 0x28FA, "source_offsets": ["0x88"], "expression": "vtable call on param_1 + 0x88 -> key 0x28fa"},
        "30a5": {"key_id": 0x30A5, "source_offsets": ["0x104"], "expression": "param_1 + 0x104 != 0 -> key 0x30a5"},
        "30a6": {"key_id": 0x30A6, "source_offsets": ["0x100"], "expression": "param_1 + 0x100 != 0 -> key 0x30a6"},
    }
    return ref, pseudo, associations


def _compiled_records(profile: Mapping[str, Any], contract: Mapping[str, Any], exe: Path) -> dict[str, Any]:
    token_records = contract.get("compiled_token_records", {})
    _require(isinstance(token_records, Mapping) and token_records, "compiled_token_records_missing")
    layouts = {
        (tuple(record.get("record_array_rva", [])), record.get("stride"))
        for record in token_records.values()
        if isinstance(record, Mapping)
    }
    _require(len(layouts) == 1, f"record_layouts_disagree:{layouts}")
    (record_array, stride), = layouts
    _require(len(record_array) == 2 and stride == 0x208, "record_layout_contract_unexpected")
    array_start = _hex_int(record_array[0], "record_array.start")
    array_end = _hex_int(record_array[1], "record_array.end")
    _require(array_end > array_start and (array_end - array_start) % stride == 0, "record_array_bounds_invalid")
    total_bytes, exe_sha = sha256_file(exe)
    _require(exe_sha == EXPECTED_EXE_SHA256, "fixed_executable_sha256_mismatch")
    table = _read_pe_rva_bounded(exe, array_start, array_end - array_start)
    _require(len(table) == array_end - array_start, "record_table_read_size_mismatch")
    slots: dict[int, list[dict[str, Any]]] = {key_id: [] for key_id in REQUESTED_KEY_IDS}
    for index in range((array_end - array_start) // stride):
        slot_rva = array_start + index * stride
        slot = table[index * stride : (index + 1) * stride]
        key_id = int.from_bytes(slot[:4], "little", signed=False)
        if key_id not in slots:
            continue
        tail = slot[4:]
        name_end = tail.find(b"\0")
        _require(name_end >= 0, f"record_name_not_terminated:{hex(key_id)}")
        try:
            name = tail[:name_end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError(f"record_name_not_ascii:{hex(key_id)}") from exc
        raw_prefix = slot[: 4 + name_end + 1]
        slots[key_id].append(
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
                "semantic_status": "name_and_key_observed_field_semantics_unresolved",
            }
        )
    records: list[dict[str, Any]] = []
    for key_id in REQUESTED_KEY_IDS:
        matches = slots[key_id]
        _require(len(matches) == 1, f"record_key_not_unique:{hex(key_id)}:{len(matches)}")
        records.append(matches[0])
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
            "slot_count": (array_end - array_start) // stride,
            "record_bytes_read_per_slot": stride,
            "array_end_semantics": "exclusive",
        },
        "records": records,
    }


def build() -> dict[str, Any]:
    if OUTPUT.exists():
        raise FileExistsError(f"refusing_to_overwrite:{OUTPUT}")
    _require(DEFAULT_EXE.is_file(), f"fixed_executable_missing:{DEFAULT_EXE}")
    writer_ref, writer_pseudo, associations = _writer_reference()
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
    records = _compiled_records(profile, contract, DEFAULT_EXE)
    return {
        "schema": "information_battle_save_key_inventory_v1",
        "status": "static_compiled_records_observed_runtime_override_unresolved",
        "scope": {
            "read_only": True,
            "game_version": "1.37.4",
            "target_executable_sha256": EXPECTED_EXE_SHA256,
            "native_function_invoked": False,
            "game_or_rpm_access": False,
            "semantic_field_mapping": False,
        },
        "writer": {
            **writer_ref,
            "selected_key_ids": [hex(key_id) for key_id in REQUESTED_KEY_IDS],
            "static_source_associations": list(associations.values()),
            "interpretation": "writer literals and source offsets are static expressions only; they do not establish field type, unit, side, or battle-result semantics",
        },
        "compiled_record_inventory": records,
        "legacy_layout_evidence": {
            "profile": {"path": relpath(PROFILE), "bytes": profile_size, "sha256": profile_sha, "profile_id": profile.get("profile_id")},
            "contract": {"path": relpath(CONTRACT), "bytes": contract_size, "sha256": contract_sha, "contract_id": contract.get("contract_id")},
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
            "The record names are compiled initializer bytes, not proof of current runtime key-vector membership.",
            "The 0x1dd240 writer contains conditional and vtable-derived sources; only literal key IDs and source expressions are recorded.",
            "No ID is assigned a battle field, unit, sign, scope, or save semantic by this inventory.",
            "The existing initializer/resolver/vector Evidence IDs are static REA references and do not authorize a runtime call or dispatch.",
        ],
        "goal_complete": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    value = build()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    OUTPUT.write_bytes(raw)
    print(json.dumps({"status": "passed", "path": relpath(OUTPUT), "bytes": len(raw), "sha256": sha256_bytes(raw)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
