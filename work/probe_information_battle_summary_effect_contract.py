"""Bounded, read-only audit of two existing battle-summary REA dossiers.

The tool never invokes REA, a game process, or native code.  It reads only the
two small evidence dossiers, their request/run receipts, the previously pinned
summary-copy fixture, and the immutable 18-record raw capture.  It extracts
mechanical strings and machine write rows; it intentionally does not promote
the raw slots to units, side roles, winners, visibility, or business effects.
Reports are exclusive.  ``--verify-existing`` reruns the bounded checks and
verifies the existing report's source pins without overwriting it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024

EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
ADAPTER_SHA256 = "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d"
MANIFEST_SHA256 = "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a"
DATABASE_SHA256 = "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161"

EFFECTS_BASE = Path("work/runtime/information-battle-business-20261025-001/rea-result-summary-effects-001")
PRESTIGE_BASE = Path("work/runtime/information-battle-business-20261025-001/rea-result-summary-prestige-001")
SUMMARY_REPORT = Path("work/runtime/information-battle-observer-20261025-001/summary-test-001/report.json")
RAW_ACCEPTANCE = Path("work/runtime/information-battle-live-20261025-001/natural-capture-acceptance-001.json")
RAW_REPORT = Path("work/runtime/information-battle-live-20261025-001/raw-after-window-002.json")
RAW_REOPEN = Path("work/runtime/information-battle-live-20261025-001/raw-reopen-001.json")

PINNED_FILES = (
    ("effects_evidence", EFFECTS_BASE / "evidence.json"),
    ("effects_request", EFFECTS_BASE / "request.json"),
    ("effects_run", EFFECTS_BASE / "run.json"),
    ("prestige_evidence", PRESTIGE_BASE / "evidence.json"),
    ("prestige_request", PRESTIGE_BASE / "request.json"),
    ("prestige_run", PRESTIGE_BASE / "run.json"),
    ("summary_header", Path("work/native/information-battle-owned-summary.h")),
    ("summary_builder_cpp", Path("work/native/test-information-battle-owned-summary.cpp")),
    ("summary_builder_python", Path("work/test_information_battle_owned_summary.py")),
    ("summary_fixture_report", SUMMARY_REPORT),
    ("summary_fixture_executable", Path("work/runtime/information-battle-observer-20261025-001/summary-test-001/test-information-battle-owned-summary.exe")),
    ("natural_capture_acceptance", RAW_ACCEPTANCE),
    ("raw_18_report", RAW_REPORT),
    ("raw_reopen_report", RAW_REOPEN),
)


def _rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def _pin(path: Path) -> dict[str, Any]:
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise RuntimeError(f"input exceeds bounded audit budget: {_rel(path)} ({size})")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return {"path": _rel(path), "size_bytes": size, "sha256": digest.hexdigest()}


def _load_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise RuntimeError(f"JSON exceeds bounded audit budget: {_rel(path)}")
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise TypeError(f"expected object JSON: {_rel(path)}")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _lines_containing(text: str, needle: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if needle in line]


def _audit_receipt(label: str, base: Path, expected_node: str, evidence: dict[str, Any]) -> dict[str, Any]:
    request = _load_json(base / "request.json")
    run = _load_json(base / "run.json")
    _require(request.get("target_sha256") == EXE_SHA256, f"{label}: request target pin")
    _require(request.get("node") == expected_node, f"{label}: request node")
    _require(request.get("procedure") == f"0x140{expected_node[2:]}", f"{label}: request procedure")
    _require(request.get("adapter_sha256") == ADAPTER_SHA256, f"{label}: adapter pin")
    _require(request.get("completed_manifest_sha256") == MANIFEST_SHA256, f"{label}: manifest pin")
    _require(request.get("completed_database_sha256") == DATABASE_SHA256, f"{label}: database pin")
    _require(request.get("query_reanalysis") is False, f"{label}: query reanalysis")
    _require(request.get("process_memory_limit_bytes") == 1_073_741_824, f"{label}: process memory limit")

    profile = evidence.get("analysis_profile", {}).get("parameters", {})
    for key, expected in {
        "local_adapter_sha256": ADAPTER_SHA256,
        "completed_manifest_sha256": MANIFEST_SHA256,
        "completed_database_sha256": DATABASE_SHA256,
        "query_reanalysis": False,
        "import_mode": "persistent-completed-project-read-only",
        "database_mutation": "read-only-no-save",
        "process_launch": "official-headless-script-v1",
    }.items():
        _require(profile.get(key) == expected, f"{label}: evidence profile {key}")

    _require(run.get("status") == "completed", f"{label}: run status")
    _require(run.get("provider_exit_code") == 0, f"{label}: provider exit")
    _require(run.get("wrapper_exit_code") == 0, f"{label}: wrapper exit")
    _require(run.get("exit_code") == 0, f"{label}: process exit")
    _require(run.get("supervisor_reason") == "completed", f"{label}: supervisor")
    _require(run.get("postread", {}).get("status") == "read", f"{label}: postread")
    _require(run.get("postread_exit_code") == 0, f"{label}: postread exit")
    cleanup = run.get("cleanup", {})
    _require(cleanup.get("status") == "complete", f"{label}: cleanup status")
    _require(cleanup.get("errors") == [], f"{label}: cleanup errors")
    _require(cleanup.get("closed_process_receipt") is True, f"{label}: closed process receipt")
    database = run.get("database", {})
    _require(database.get("status") == "matched", f"{label}: database status")
    _require(database.get("unchanged") is True, f"{label}: database unchanged")
    processes = run.get("processes")
    _require(isinstance(processes, list) and len(processes) == 1, f"{label}: process receipt count")
    process = processes[0]
    _require(process.get("still_running_same_process") is False, f"{label}: process still running")
    peak = process.get("peak_committed_bytes")
    _require(isinstance(peak, int) and peak < 1_073_741_824, f"{label}: peak memory")
    _require(run.get("evidence_id") == evidence.get("evidence_id"), f"{label}: evidence receipt ID")

    return {
        "request": {
            "node": request["node"],
            "procedure": request["procedure"],
            "target_sha256": request["target_sha256"],
            "query_reanalysis": request["query_reanalysis"],
            "process_memory_limit_bytes": request["process_memory_limit_bytes"],
        },
        "run": {
            "status": run["status"],
            "provider_exit_code": run["provider_exit_code"],
            "wrapper_exit_code": run["wrapper_exit_code"],
            "exit_code": run["exit_code"],
            "elapsed_seconds": run.get("elapsed_seconds"),
            "peak_committed_bytes": peak,
            "cleanup_status": cleanup["status"],
            "closed_process_receipt": cleanup["closed_process_receipt"],
            "database_status": database["status"],
            "database_unchanged": database["unchanged"],
        },
        "analysis_profile": {
            "adapter_sha256": profile["local_adapter_sha256"],
            "completed_manifest_sha256": profile["completed_manifest_sha256"],
            "completed_database_sha256": profile["completed_database_sha256"],
            "import_mode": profile["import_mode"],
            "database_mutation": profile["database_mutation"],
            "process_launch": profile["process_launch"],
        },
    }


def _audit_function(label: str, path: Path, expected: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    evidence = _load_json(path)
    normalized = evidence.get("normalized_result", {})
    procedure = normalized.get("procedure", {})
    _require(evidence.get("evidence_id") == expected["evidence_id"], f"{label}: evidence id")
    _require(evidence.get("subject", {}).get("digest", {}).get("sha256") == EXE_SHA256, f"{label}: executable pin")
    _require(evidence.get("provider", {}).get("id") == "ghidra", f"{label}: provider")
    _require(procedure.get("name") == expected["procedure_name"], f"{label}: procedure name")
    _require(procedure.get("address") == expected["procedure_va"], f"{label}: procedure address")
    body = procedure.get("body", {})
    _require(body.get("available") is True, f"{label}: body availability")
    _require(body.get("total_bytes") == expected["body_bytes"], f"{label}: body bytes")
    _require(body.get("non_contiguous") is False, f"{label}: body contiguous")
    _require(body.get("ranges") == [{"start": expected["body_start"], "end": expected["body_end_inclusive"]}], f"{label}: inclusive body range")

    pseudocode = normalized.get("pseudocode", "")
    _require(expected["diagnostic"] in pseudocode, f"{label}: diagnostic string")
    diagnostic_lines = _lines_containing(pseudocode, expected["diagnostic"])
    _require(diagnostic_lines, f"{label}: diagnostic line missing")
    for needle in expected["pseudocode_needles"]:
        _require(needle in pseudocode, f"{label}: pseudocode needle {needle}")

    assembly = normalized.get("assembly", [])
    _require(isinstance(assembly, list), f"{label}: assembly list")
    write_rows = [line for line in assembly if any(needle in line for needle in expected["assembly_write_needles"])]
    _require(write_rows == expected["assembly_write_rows"], f"{label}: exact assembly write rows")
    callees = normalized.get("callees", [])
    callee_addresses = [item.get("address") for item in callees]
    for address in expected["unresolved_callees"]:
        _require(address in callee_addresses, f"{label}: unresolved callee {address}")

    result = {
        "label": label,
        "evidence_id": evidence["evidence_id"],
        "procedure": {
            "name": procedure["name"],
            "rva": expected["rva"],
            "va": procedure["address"],
            "body_start": expected["body_start"],
            "body_end_inclusive": expected["body_end_inclusive"],
            "body_bytes": body["total_bytes"],
            "end_semantics": "inclusive (end-start+1 equals total_bytes)",
        },
        "diagnostic": {
            "string": expected["diagnostic"],
            "pseudocode_lines": diagnostic_lines,
        },
        "proof_expression": {
            "pseudocode_lines": [
                line.strip() for line in pseudocode.splitlines()
                if any(needle in line for needle in expected["pseudocode_needles"])
            ],
            "machine_write_rows": write_rows,
        },
        "unresolved_callees": [
            {"address": address, "semantic_status": "unknown; no unit/side-effect/business interpretation"}
            for address in expected["unresolved_callees"]
        ],
        "static_status": "observed_static_game_path_not_getter",
    }
    return result, evidence


def _audit_summary_and_raw() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    summary = _load_json(SUMMARY_REPORT)
    _require(summary.get("status") == "passed", "summary fixture status")
    contract = summary.get("contract", {})
    expected_offsets = [f"0x{offset:02x}" for offset in range(0x20, 0x4a, 4)]
    _require(contract.get("raw_i32_offsets") == expected_offsets, "summary raw offset table")
    _require(contract.get("control_byte_offset") == "0x4c", "summary control offset")
    _require(contract.get("read_span") == {"bytes": 45, "end_offset_exclusive": "0x4d", "start_offset": "0x20"}, "summary read span")
    _require(contract.get("reader_signature") == "bool read(uintptr_t,unsigned char*,size_t) noexcept", "summary reader signature")
    _require(contract.get("max_total_read_bytes") == 256, "summary total budget")
    _require(contract.get("failure_output_unchanged") is True, "summary failure atomicity")
    _require(contract.get("output_contains_only_raw_values") is True, "summary raw-only output")
    _require(contract.get("semantic_interpretation") == {"kind": "unknown", "side_role": "unknown", "units": "unknown", "visibility": "unknown"}, "summary semantic boundary")
    observations = summary.get("observations", {})
    _require(observations.get("result") == "RESULT PASS", "summary fixture result")
    _require(observations.get("check_count") == 24, "summary fixture check count")

    acceptance = _load_json(RAW_ACCEPTANCE)
    _require(acceptance.get("status") == "passed_raw_capture_business_unverified", "natural acceptance status")
    _require(acceptance.get("captured") == 18, "natural capture count")
    _require(acceptance.get("raw_payloads_strictly_decoded") == 18, "natural decoded count")
    _require(acceptance.get("business_battle_complete") is False, "natural business completeness")
    _require(acceptance.get("visibility_verified") is False, "natural visibility")
    _require(acceptance.get("goal_complete") is False, "natural goal completion")

    raw = _load_json(RAW_REPORT)
    _require(raw.get("status") == "passed", "raw report status")
    _require(raw.get("completeness", {}).get("business_complete") is False, "raw business completeness")
    _require(raw.get("completeness", {}).get("battle_complete") is False, "raw battle completeness")
    _require(raw.get("completeness", {}).get("overall_complete") is False, "raw overall completeness")
    _require(raw.get("completeness", {}).get("visibility_verified") is False, "raw visibility")
    _require(raw.get("completeness", {}).get("public_identity", {}).get("status") == "absent", "raw public identity")
    scope = raw.get("scope", {})
    _require(scope.get("game_access") is False and scope.get("native_game_function_invoked") is False and scope.get("process_access") is False, "raw scope")
    messages = raw.get("messages", [])
    _require(len(messages) == 18, "raw message count")
    observations: list[dict[str, Any]] = []
    for expected_sequence, message in enumerate(messages, 1):
        value = message.get("decode", {}).get("value", {})
        observation = value.get("observation", {})
        result = observation.get("result", {})
        summary_value = observation.get("summary", {})
        _require(observation.get("sequence") == expected_sequence, f"raw sequence {expected_sequence}")
        raw_i32 = summary_value.get("raw_i32")
        _require(isinstance(raw_i32, list) and len(raw_i32) == 11, f"raw summary slot count {expected_sequence}")
        _require(message.get("raw_payload_complete") is True and message.get("transport_complete") is True, f"raw completion {expected_sequence}")
        observations.append({
            "sequence": expected_sequence,
            "raw_date": result.get("raw_date"),
            "summary_raw_i32": raw_i32,
            "control_byte": summary_value.get("control_byte"),
            "payload_bytes": message.get("payload_bytes"),
            "payload_sha256": message.get("payload_sha256"),
            "semantic_status": "recorded_raw_slot_values_only",
        })

    reopened = _load_json(RAW_REOPEN)
    _require(reopened.get("status") == "passed", "raw reopen status")
    first = [(m.get("message_id"), m.get("payload_sha256")) for m in messages]
    second = [(m.get("message_id"), m.get("payload_sha256")) for m in reopened.get("messages", [])]
    _require(first == second, "raw reopen message identity/hash")
    return {
        "summary_fixture": {
            "status": summary["status"],
            "check_count": observations_count_from_summary(summary),
            "reader_signature": contract["reader_signature"],
            "raw_i32_offsets": expected_offsets,
            "control_byte_offset": contract["control_byte_offset"],
            "read_span_bytes": contract["read_span"]["bytes"],
            "semantic_interpretation": contract["semantic_interpretation"],
            "source_layout_admitted": contract["source_layout_admitted"],
        },
        "natural_capture": {
            "status": acceptance["status"],
            "captured": acceptance["captured"],
            "sequence_range": acceptance["sequence_range"],
            "raw_payloads_strictly_decoded": acceptance["raw_payloads_strictly_decoded"],
            "dropped_or_failed_reported": acceptance["dropped_or_failed_reported"],
            "business_battle_complete": acceptance["business_battle_complete"],
            "visibility_verified": acceptance["visibility_verified"],
            "goal_complete": acceptance["goal_complete"],
        },
        "raw_report": {
            "status": raw["status"],
            "message_count": len(messages),
            "sequence_range": [1, 18],
            "business_complete": raw["completeness"]["business_complete"],
            "battle_complete": raw["completeness"]["battle_complete"],
            "overall_complete": raw["completeness"]["overall_complete"],
            "visibility_verified": raw["completeness"]["visibility_verified"],
            "public_identity": raw["completeness"]["public_identity"],
            "reopen_same_message_hashes": True,
        },
    }, observations


def observations_count_from_summary(summary: dict[str, Any]) -> int:
    return int(summary.get("observations", {}).get("check_count", 0))


def _build_report() -> dict[str, Any]:
    effects_expected = {
        "evidence_id": "ev_c2d6024f70e1aa326289bc51e11017660d51b37e8da474becff63aea6e92c0a9",
        "procedure_name": "FUN_1402367a0",
        "procedure_va": "0x1402367a0",
        "rva": "0x2367a0",
        "body_start": "0x1402367a0",
        "body_end_inclusive": "0x140236db3",
        "body_bytes": 1556,
        "diagnostic": '"Tradition, %d, %d, %d, %d, %d, %d, %d, %d"',
        "pseudocode_needles": ["*(int *)(param_2 + 0x20)", "*(int *)(param_2 + 0x24)", "*(char *)(param_2 + 0x4c)"],
        "assembly_write_needles": [
            "ADD dword ptr [R13 + 0x20]",
            "MOV dword ptr [R13 + 0x24]",
            "MOV dword ptr [R13 + 0x20]",
            "MOV dword ptr [R13 + 0x24]",
        ],
        "assembly_write_rows": [
            "0x140236d50: ADD dword ptr [R13 + 0x20], EAX",
            "0x140236d89: MOV dword ptr [R13 + 0x24], EDX",
            "0x140236d98: MOV dword ptr [R13 + 0x20], EDX",
            "0x140236d9c: MOV dword ptr [R13 + 0x24], EAX",
        ],
        "unresolved_callees": ["0x14021ff90", "0x140d731a0"],
    }
    prestige_expected = {
        "evidence_id": "ev_000f8a07c19511650a25705c8b7574392b185bdb524ca4efee8f554e06116aac",
        "procedure_name": "FUN_140236dc0",
        "procedure_va": "0x140236dc0",
        "rva": "0x236dc0",
        "body_start": "0x140236dc0",
        "body_end_inclusive": "0x140237144",
        "body_bytes": 901,
        "diagnostic": '"GainPrestige, %d, %d, %d, %d, %d, %d, %d"',
        "pseudocode_needles": ["*(int *)(param_2 + 0x28)", "*(int *)(param_2 + 0x2c)", "*(char *)(param_2 + 0x4c)"],
        "assembly_write_needles": [
            "ADD dword ptr [R15 + 0x28]",
            "ADD dword ptr [R15 + 0x2c]",
            "MOV dword ptr [R15 + 0x28]",
            "MOV dword ptr [R15 + 0x2c]",
        ],
        "assembly_write_rows": [
            "0x14023709a: ADD dword ptr [R15 + 0x28], EAX",
            "0x140237119: ADD dword ptr [R15 + 0x2c], EAX",
            "0x14023712c: MOV dword ptr [R15 + 0x28], ECX",
            "0x140237130: MOV dword ptr [R15 + 0x2c], EAX",
        ],
        "unresolved_callees": ["0x140220480"],
    }

    effects, effects_evidence = _audit_function("tradition", EFFECTS_BASE / "evidence.json", effects_expected)
    prestige, prestige_evidence = _audit_function("prestige", PRESTIGE_BASE / "evidence.json", prestige_expected)
    effects_receipt = _audit_receipt("tradition", EFFECTS_BASE, "0x2367a0", effects_evidence)
    prestige_receipt = _audit_receipt("prestige", PRESTIGE_BASE, "0x236dc0", prestige_evidence)
    recorded, observations = _audit_summary_and_raw()

    source_pins = []
    for role, path in PINNED_FILES:
        pin = _pin(path)
        pin["role"] = role
        source_pins.append(pin)
    audit_script_pin = _pin(Path(__file__))
    audit_script_pin["role"] = "audit_script"
    source_pins.append(audit_script_pin)

    summary_slots = []
    for index, offset in enumerate(range(0x20, 0x4A, 4)):
        if index in (0, 1):
            label = "tradition_related_raw_slot"
        elif index in (2, 3):
            label = "prestige_related_raw_slot"
        else:
            label = "uninterpreted_raw_summary_slot"
        summary_slots.append({
            "raw_i32_index": index,
            "offset": f"0x{offset:02x}",
            "label": label,
            "unit": "unknown",
            "side_role": "unknown",
            "winner_or_loss_semantics": "unknown",
            "observer_role": "unknown",
        })

    return {
        "schema": "information_battle_summary_effect_contract_v1",
        "status": "static_evidence_and_recorded_projection_passed",
        "goal_complete": False,
        "scope": {
            "read_only": True,
            "new_rea_or_rpm": False,
            "game_process_access": False,
            "native_getter_invoked": False,
            "production_modified": False,
            "old_reports_modified": False,
            "raw_values_are_recorded_observations": True,
            "business_effects_available": False,
        },
        "target": {
            "game_version": "1.37.4",
            "executable_sha256": EXE_SHA256,
            "image_base": "0x140000000",
            "address_convention": "RVA is reported separately from VA; REA body end is preserved as inclusive because end-start+1 equals total_bytes",
        },
        "rea_evidence": {
            "tradition": effects,
            "prestige": prestige,
        },
        "execution_receipts": {
            "tradition": effects_receipt,
            "prestige": prestige_receipt,
        },
        "summary_layout": {
            "source_status": "selected_static_field_table_plus_fixture_copy",
            "raw_i32_offsets": [f"0x{offset:02x}" for offset in range(0x20, 0x4A, 4)],
            "control_byte_offset": "0x4c",
            "read_span": {"start_offset": "0x20", "end_offset_exclusive": "0x4d", "bytes": 45},
            "raw_slot_labels": summary_slots,
            "control_semantics": "branch/control byte only; the 0x4c-dependent swaps are observed, but its business meaning is unknown",
            "swap_contract": [
                {"function": "tradition", "when": "param_2+0x4c != 0", "pairs": [["0x20", "0x24"]]},
                {"function": "prestige", "when": "param_2+0x4c != 0", "pairs": [["0x28", "0x2c"]]},
            ],
        },
        "recorded_raw_observations": {
            "source_report": _rel(RAW_REPORT),
            "count": len(observations),
            "observation_status": "recorded_raw_slot_values_only",
            "values": observations,
            "not_proof_of": [
                "Tradition or prestige business units",
                "winner, side orientation, loss, army/navy quantity semantics",
                "observer role or visibility",
                "function output/effect causality",
                "all natural battles or complete B01-B04 coverage",
            ],
        },
        "source_pins": source_pins,
        "unresolved_conditions": [
            {
                "address": "0x21ff90",
                "used_by": "2367A0 Tradition path",
                "status": "unknown",
                "reason": "callee return value and side effects are not assigned units or business meaning here",
            },
            {
                "address": "0xd731a0",
                "used_by": "2367A0 Tradition path and 236DC0 GainPrestige path",
                "status": "unknown",
                "reason": "helper output/side effects remain unresolved; no native getter call is authorized",
            },
            {
                "address": "0x220480",
                "used_by": "236DC0 GainPrestige path",
                "status": "unknown",
                "reason": "helper output/side effects remain unresolved; no prestige getter interpretation is made",
            },
            {
                "address": "0x4c",
                "used_by": "both functions",
                "status": "branch_observed_semantics_unknown",
                "reason": "nonzero selects a pair exchange, but its source field/side meaning is not established",
            },
        ],
        "business_boundary": {
            "tradition_function": "static game-path diagnostic plus writes to raw summary offsets 0x20/0x24; not an active getter",
            "prestige_function": "static game-path diagnostic plus writes to raw summary offsets 0x28/0x2c; not an active getter",
            "promotion_to_information_fields": False,
            "promotion_to_B01_B04": False,
            "visibility_verified": False,
            "public_war_or_battle_identity": False,
            "units_and_effects": "unknown",
        },
        "limitations": [
            "REA pseudocode and assembly are static shipped-artifact evidence, not original source or runtime behavior.",
            "The two functions are game paths and were not actively called as getters.",
            "The 18 raw summary arrays are recorded observations from a real capture, but the capture explicitly remains business/battle/overall incomplete and visibility-unverified.",
            "The old summary copy fixture proves bounded raw copying and failure atomicity only; it does not prove these two function effects or field semantics.",
        ],
    }


def _verify_existing(path: Path) -> int:
    existing = _load_json(path)
    current = _build_report()
    mismatches: list[str] = []
    if existing.get("schema") != current["schema"]:
        mismatches.append("schema")
    old_pins = {item["path"]: item for item in existing.get("source_pins", [])}
    for item in current["source_pins"]:
        old = old_pins.get(item["path"])
        if not old:
            mismatches.append(f"missing pin:{item['path']}")
            continue
        for key in ("size_bytes", "sha256"):
            if old.get(key) != item.get(key):
                mismatches.append(f"{item['path']}:{key}")
    result = {
        "verified": not mismatches,
        "report": _rel(path),
        "source_pin_count": len(current["source_pins"]),
        "mismatches": mismatches,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not mismatches else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("work/runtime/information-battle-business-20261025-001/summary-effect-contract-001.json"))
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args(argv)
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if args.verify_existing:
        if not output.is_file():
            raise SystemExit(f"missing report: {output}")
        return _verify_existing(output)
    report = _build_report()
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_REPORT_BYTES:
        raise SystemExit(f"report exceeds bounded output budget: {len(encoded)}")
    try:
        with output.open("xb") as stream:
            stream.write(encoded)
    except FileExistsError:
        raise SystemExit(f"refusing to overwrite existing report: {output}")
    print(json.dumps({"created": True, "path": _rel(output), "bytes": len(encoded), "source_pin_count": len(report["source_pins"])}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
