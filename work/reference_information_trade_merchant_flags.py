"""Reproduce raw merchant-state fields from the archived trade-entry capture.

This script is deliberately independent of the production reader.  It only
uses the archived two-pass 0xc0-byte entries and the top-level identity fields
of the frozen batch-46 expected report.  It does not call the game, RPM, REA,
or any native function.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any


ENTRY_SIZE = 0xC0
EXPECTED_NODE_COUNT = 80
EXPECTED_TRUE_PREDICATE = "0x8f440"
EXPECTED_FALSE_PREDICATE = "0x8f450"
EXPECTED_VERSION = "1.37.4"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_COUNTRY = "FRA"
EXPECTED_DATE = 56557728
EXPECTED_SESSION = "31460-1dd653f69242d7b"
EXPECTED_PID = 31460
EXPECTED_CREATION_FILETIME = 134374886912306555
EXPECTED_FULLREF_HEX = "465241007a000001"
EXPECTED_COUNTRY_SLOT = 122


def _load(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _u32(raw: bytes) -> int:
    _require(len(raw) == 4, "DWORD slice must be four bytes")
    return int.from_bytes(raw, "little", signed=False)


def _s32(raw: bytes) -> int:
    _require(len(raw) == 4, "DWORD slice must be four bytes")
    return int.from_bytes(raw, "little", signed=True)


def _s8(raw: bytes) -> int:
    _require(len(raw) == 1, "byte slice must be one byte")
    return int.from_bytes(raw, "little", signed=True)


def _byte_value(raw: bytes, offset: int) -> dict[str, Any]:
    value = raw[offset:offset + 1]
    _require(len(value) == 1, f"byte range outside entry: {offset:#x}")
    unsigned = value[0]
    return {
        "offset": hex(offset),
        "raw_hex": value.hex(),
        "unsigned": unsigned,
        "signed": _s8(value),
    }


def _dword_value(raw: bytes, offset: int) -> dict[str, Any]:
    value = raw[offset:offset + 4]
    _require(len(value) == 4, f"DWORD range outside entry: {offset:#x}")
    return {
        "offset": hex(offset),
        "raw_hex": value.hex(),
        "unsigned": _u32(value),
        "signed": _s32(value),
    }


def _identity_from_pass(pass_data: dict[str, Any]) -> dict[str, Any]:
    date = pass_data.get("date")
    _require(isinstance(date, dict), "pass date metadata missing")
    country = pass_data.get("country")
    _require(isinstance(country, dict), "pass country metadata missing")
    return {
        "date": date.get("value"),
        "date_raw_hex": date.get("raw_hex"),
        "country": pass_data.get("country"),
        "country_reference_raw_hex": pass_data.get("country_reference_raw_hex"),
        "country_slot": pass_data.get("country_slot"),
        "module_base": pass_data.get("module_base"),
    }


def _check_pass(pass_data: dict[str, Any], index: int) -> None:
    country = pass_data.get("country")
    _require(isinstance(country, dict) and country.get("requested_country") == EXPECTED_COUNTRY, f"pass {index}: country mismatch")
    _require(pass_data.get("true_node_count") == EXPECTED_NODE_COUNT, f"pass {index}: true count mismatch")
    _require(pass_data.get("false_node_count") == 1, f"pass {index}: false count mismatch")
    _require(pass_data.get("entry_read_bytes") == EXPECTED_NODE_COUNT * ENTRY_SIZE, f"pass {index}: byte count mismatch")
    _require(pass_data.get("country_reference_raw_hex") == EXPECTED_FULLREF_HEX, f"pass {index}: fullref mismatch")
    _require(pass_data.get("country_slot") == EXPECTED_COUNTRY_SLOT, f"pass {index}: slot mismatch")
    _require(pass_data.get("date", {}).get("value") == EXPECTED_DATE, f"pass {index}: date mismatch")
    contract = pass_data.get("entry_capture_contract")
    _require(isinstance(contract, dict), f"pass {index}: entry contract missing")
    _require(contract.get("entry_size_bytes") == ENTRY_SIZE, f"pass {index}: entry size mismatch")
    _require(contract.get("true_predicate_rva") == EXPECTED_TRUE_PREDICATE, f"pass {index}: predicate mismatch")
    _require(contract.get("false_definition_action") == "skip_entry_read_only_Null", f"pass {index}: false-node action mismatch")
    _require(contract.get("raw_only") is True, f"pass {index}: raw-only contract missing")
    skipped = pass_data.get("skipped_false_nodes")
    _require(isinstance(skipped, list) and len(skipped) == 1, f"pass {index}: skipped false-node count mismatch")
    false_node = skipped[0]
    _require(false_node.get("node_id") == "Null", f"pass {index}: false node identity mismatch")
    _require(false_node.get("predicate_rva") == EXPECTED_FALSE_PREDICATE, f"pass {index}: false predicate mismatch")
    _require(false_node.get("entry_read") is False, f"pass {index}: false node was read")
    nodes = pass_data.get("trade_entry_nodes")
    _require(isinstance(nodes, list) and len(nodes) == EXPECTED_NODE_COUNT, f"pass {index}: node count mismatch")
    seen: set[str] = set()
    for node_index, node in enumerate(nodes):
        _require(isinstance(node, dict), f"pass {index} node {node_index}: object missing")
        node_id = node.get("node_id")
        _require(isinstance(node_id, str) and node_id and node_id not in seen, f"pass {index}: duplicate node id")
        seen.add(node_id)
        _require(node.get("predicate_rva") == EXPECTED_TRUE_PREDICATE, f"pass {index} {node_id}: predicate mismatch")
        _require(node.get("entry_read") is True, f"pass {index} {node_id}: entry not marked read")
        _require(node.get("entry_size_bytes") == ENTRY_SIZE, f"pass {index} {node_id}: entry size mismatch")
        raw_hex = node.get("entry_raw_hex")
        _require(isinstance(raw_hex, str) and len(raw_hex) == ENTRY_SIZE * 2, f"pass {index} {node_id}: raw length mismatch")
        raw = bytes.fromhex(raw_hex)
        _require(len(raw) == ENTRY_SIZE, f"pass {index} {node_id}: raw byte range mismatch")
        _require(node.get("entry_span_hex") == "0xc0", f"pass {index} {node_id}: span mismatch")


def _decode_node(node: dict[str, Any]) -> dict[str, Any]:
    raw = bytes.fromhex(node["entry_raw_hex"])
    flags = {
        label: _byte_value(raw, offset)
        for label, offset in (("ac", 0xAC), ("ad", 0xAD), ("ae", 0xAE), ("af", 0xAF))
    }
    dwords = {
        label: _dword_value(raw, offset)
        for label, offset in (("a0", 0xA0), ("a4", 0xA4), ("a8", 0xA8))
    }
    return {
        "node_id": node["node_id"],
        "predicate_rva": node["predicate_rva"],
        "entry_address": node["entry_address"],
        "entry_address_kind": "runtime_va_or_heap; not an RVA",
        "entry_span": "[entry_address, entry_address+0xc0)",
        "entry_size_bytes": ENTRY_SIZE,
        "entry_raw_hex": node["entry_raw_hex"],
        "flags_ac_ad_ae_af_hex": raw[0xAC:0xB0].hex(),
        "flags": flags,
        "dwords": dwords,
    }


def _group_counts(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    flag_groups: Counter[str] = Counter(node["flags_ac_ad_ae_af_hex"] for node in nodes)
    flag_byte_groups: dict[str, dict[str, int]] = {}
    for label in ("ac", "ad", "ae", "af"):
        flag_byte_groups[label] = dict(sorted(Counter(node["flags"][label]["raw_hex"] for node in nodes).items()))
    dword_groups: dict[str, Any] = {}
    for label in ("a0", "a4", "a8"):
        dword_groups[label] = {
            "raw_hex": dict(sorted(Counter(node["dwords"][label]["raw_hex"] for node in nodes).items())),
            "unsigned": {str(k): v for k, v in sorted(Counter(node["dwords"][label]["unsigned"] for node in nodes).items())},
            "signed": {str(k): v for k, v in sorted(Counter(node["dwords"][label]["signed"] for node in nodes).items())},
        }
    return {
        "flags_ac_ad_ae_af_hex": {key: flag_groups[key] for key in sorted(flag_groups)},
        "flag_bytes": flag_byte_groups,
        "dwords": dword_groups,
        "flag_groups_with_nodes": [
            {
                "raw_hex": key,
                "count": flag_groups[key],
                "node_ids": [node["node_id"] for node in nodes if node["flags_ac_ad_ae_af_hex"] == key],
            }
            for key in sorted(flag_groups)
        ],
    }


def build_report(source: dict[str, Any], expected: dict[str, Any], source_path: Path, expected_path: Path) -> dict[str, Any]:
    _require(source.get("schema") == "information_independent_trade_entry_inputs.v1", "unexpected source schema")
    _require(source.get("field") == "trade_entries", "unexpected source field")
    _require(source.get("target_build", {}).get("version") == EXPECTED_VERSION, "source version mismatch")
    _require(source.get("target_build", {}).get("expected_exe_sha256") == EXPECTED_EXE_SHA256, "source EXE mismatch")
    _require(source.get("country") == EXPECTED_COUNTRY, "source country mismatch")
    _require(source.get("identity", {}).get("installation_pid") == EXPECTED_PID, "source PID mismatch")
    _require(source.get("identity", {}).get("installation_creation_filetime") == EXPECTED_CREATION_FILETIME, "source creation mismatch")
    _require(source.get("identity", {}).get("installation_session_id") == EXPECTED_SESSION, "source session mismatch")
    _require(source.get("identity", {}).get("process_path_sha256") == EXPECTED_EXE_SHA256, "source process hash mismatch")
    _require(source.get("identity", {}).get("binding_verified") is True, "source identity binding not verified")
    _require(source.get("identity", {}).get("process_creation_matches_installation") is True, "source process creation binding not verified")
    _require(source.get("identity", {}).get("process_path_sha256_matches_expected") is True, "source executable binding not verified")
    _require(source.get("native_function_invoked") is False, "source native function invocation is not false")
    access = source.get("access")
    _require(isinstance(access, dict), "source access metadata missing")
    for key in ("native_game_calls", "target_memory_writes", "dll_injection", "private_heap_scan", "ui_control", "date_advance", "save_or_reload"):
        _require(access.get(key) is False, f"source access contract failed: {key}")
    _require(source.get("cleanup", {}).get("handle_close", {}).get("closed") is True, "source handle not closed")

    _require(expected.get("schema") == "information_trade_source_details_independent_expected.v2", "unexpected expected002 schema")
    _require(expected.get("session_id") == EXPECTED_SESSION, "expected002 session mismatch")
    _require(expected.get("game_date") == EXPECTED_DATE, "expected002 date mismatch")
    _require(expected.get("country") == EXPECTED_COUNTRY, "expected002 country mismatch")
    _require(expected.get("fullref_raw_hex") == EXPECTED_FULLREF_HEX, "expected002 fullref mismatch")
    _require(expected.get("country_slot") == EXPECTED_COUNTRY_SLOT, "expected002 slot mismatch")
    _require(expected.get("node_count") == EXPECTED_NODE_COUNT, "expected002 node count mismatch")

    passes = source.get("trade_entries_inputs")
    _require(isinstance(passes, list) and len(passes) == 2, "source must contain exactly two passes")
    for index, pass_data in enumerate(passes):
        _require(isinstance(pass_data, dict), f"pass {index} is not an object")
        _check_pass(pass_data, index)

    first_nodes = passes[0]["trade_entry_nodes"]
    second_nodes = passes[1]["trade_entry_nodes"]
    decoded_nodes: list[dict[str, Any]] = []
    node_id_mismatches: list[dict[str, Any]] = []
    raw_mismatches: list[str] = []
    address_mismatches: list[str] = []
    for index, (first, second) in enumerate(zip(first_nodes, second_nodes)):
        node_id = first["node_id"]
        if first.get("node_id") != second.get("node_id"):
            node_id_mismatches.append({"index": index, "pass0": first.get("node_id"), "pass1": second.get("node_id")})
        if first.get("entry_raw_hex") != second.get("entry_raw_hex"):
            raw_mismatches.append(node_id)
        if first.get("entry_address") != second.get("entry_address"):
            address_mismatches.append(node_id)
        decoded_nodes.append(_decode_node(first))
    _require(not node_id_mismatches, "node order differs between passes")
    _require(not raw_mismatches, f"raw entry mismatch: {raw_mismatches[:3]}")
    _require(not address_mismatches, f"entry address mismatch: {address_mismatches[:3]}")

    pass_identity = [_identity_from_pass(pass_data) for pass_data in passes]
    _require(pass_identity[0] == pass_identity[1], "pass identity metadata mismatch")
    _require(pass_identity[0]["date"] == EXPECTED_DATE, "pass date mismatch")
    _require(pass_identity[0]["country_reference_raw_hex"] == EXPECTED_FULLREF_HEX, "pass fullref mismatch")
    _require(pass_identity[0]["country_slot"] == EXPECTED_COUNTRY_SLOT, "pass slot mismatch")

    pass_bytes = [b"".join(bytes.fromhex(node["entry_raw_hex"]) for node in pass_data["trade_entry_nodes"]) for pass_data in passes]
    source_identity = source["identity"]
    strict_contract = source.get("strict_identity_contract", {})
    return {
        "schema": "information.trade_merchant_flag_inputs.v1",
        "report_id": "information-trade-merchant-state-native-flag-inputs-from-archived-raw-001",
        "stage": "information-trade-merchant-state-20261027-001",
        "generated_on": "2026-10-27",
        "status": "observed_archived_two_pass_consistent",
        "evidence_kind": "archived_runtime_raw_reanalysis_not_new_capture",
        "source": {
            "path": str(source_path).replace("/", "\\"),
            "sha256": _sha256(source_path),
            "schema": source["schema"],
            "role": "authoritative archived two-pass 0xc0 entry bytes; no public expected values imported",
        },
        "expected002_identity_anchor": {
            "path": str(expected_path).replace("/", "\\"),
            "sha256": _sha256(expected_path),
            "schema": expected["schema"],
            "role": "top-level identity anchor only; its public source values and node values are not used for decoding",
            "session_id": expected["session_id"],
            "game_date": expected["game_date"],
            "country": expected["country"],
            "fullref_raw_hex": expected["fullref_raw_hex"],
            "country_slot": expected["country_slot"],
            "node_count": expected["node_count"],
        },
        "target_build": {
            "game_version": EXPECTED_VERSION,
            "exe_sha256": EXPECTED_EXE_SHA256,
            "image_base_va": "0x140000000",
            "rva_rule": "Static contract RVAs are separate from runtime VA/heap entry addresses; no new static address was decoded.",
        },
        "identity_binding": {
            "installation_pid": source_identity["installation_pid"],
            "installation_creation_filetime": source_identity["installation_creation_filetime"],
            "session_id": source_identity["installation_session_id"],
            "game_date_raw": EXPECTED_DATE,
            "country": EXPECTED_COUNTRY,
            "country_fullref_raw_hex": EXPECTED_FULLREF_HEX,
            "country_slot": EXPECTED_COUNTRY_SLOT,
            "process_path_sha256": source_identity["process_path_sha256"],
            "module_path_matches_process": source_identity["module_path_matches_process"],
            "source_binding_verified": source_identity["binding_verified"],
            "strict_identity_contract": {
                "installation_experiment": strict_contract.get("installation_experiment"),
                "pid": strict_contract.get("pid"),
                "creation_filetime": strict_contract.get("creation_filetime"),
                "session_id": strict_contract.get("session_id"),
                "game_date_raw": strict_contract.get("game_date_raw"),
                "game_version": strict_contract.get("game_version"),
                "exe_sha256": strict_contract.get("exe_sha256"),
                "checks": strict_contract.get("checks"),
            },
            "checks": {
                "source_exe_matches_expected": True,
                "source_session_matches_expected": True,
                "source_creation_matches_expected": True,
                "source_date_matches_expected": True,
                "source_country_fullref_slot_matches_expected002": True,
                "expected002_used_only_as_identity_anchor": True,
            },
        },
        "raw_byte_contract": {
            "entry_size_bytes": ENTRY_SIZE,
            "entry_span": "[entry_address, entry_address+0xc0)",
            "entry_address_kind": "runtime VA or heap address from archived capture; not a module RVA",
            "flags": {
                "ac": {"offset": "0xac", "width_bytes": 1},
                "ad": {"offset": "0xad", "width_bytes": 1},
                "ae": {"offset": "0xae", "width_bytes": 1},
                "af": {"offset": "0xaf", "width_bytes": 1},
            },
            "dwords": {
                "a0": {"offset": "0xa0", "width_bytes": 4},
                "a4": {"offset": "0xa4", "width_bytes": 4},
                "a8": {"offset": "0xa8", "width_bytes": 4},
            },
            "decoding_rule": "Only little-endian original raw bytes, unsigned and signed integer views are emitted; no business labels are assigned.",
        },
        "capture_summary": {
            "passes": 2,
            "true_nodes_per_pass": [len(first_nodes), len(second_nodes)],
            "false_nodes_per_pass": [1, 1],
            "entry_bytes_per_pass": [len(pass_bytes[0]), len(pass_bytes[1])],
            "rpm_bytes_requested": source.get("access", {}).get("rpm_bytes_requested"),
            "rpm_calls": source.get("access", {}).get("rpm_calls"),
            "native_function_invoked": source.get("native_function_invoked"),
            "handle_close": source.get("cleanup", {}).get("handle_close"),
            "no_new_capture": True,
        },
        "two_pass_consistency": {
            "node_ids_equal": not node_id_mismatches,
            "entry_raw_bytes_equal": not raw_mismatches,
            "entry_addresses_equal": not address_mismatches,
            "identity_metadata_equal": pass_identity[0] == pass_identity[1],
            "pass0_entry_bytes_sha256": hashlib.sha256(pass_bytes[0]).hexdigest(),
            "pass1_entry_bytes_sha256": hashlib.sha256(pass_bytes[1]).hexdigest(),
            "mismatches": {
                "node_ids": node_id_mismatches,
                "entry_raw": raw_mismatches,
                "entry_addresses": address_mismatches,
            },
        },
        "nodes": decoded_nodes,
        "counts": {
            "node_count": len(decoded_nodes),
            "flags_and_dwords_are_raw_views_only": True,
            **_group_counts(decoded_nodes),
        },
        "selection_boundary": {
            "true_predicate_rva": EXPECTED_TRUE_PREDICATE,
            "false_predicate_rva": EXPECTED_FALSE_PREDICATE,
            "true_nodes_included": EXPECTED_NODE_COUNT,
            "false_nodes_skipped": 1,
            "false_node_id": "Null",
            "unexpected_predicate_policy": "not applicable to this archived capture; no new node was admitted",
        },
        "verification": {
            "source_reloaded": True,
            "expected002_reloaded_identity_only": True,
            "production_reader_imported": False,
            "public_values_imported": False,
            "new_capture": False,
            "game_access": False,
            "rpm_used": False,
            "native_function_execution": False,
            "rea_access": False,
            "production_written": False,
            "old_stage_written": False,
            "handle_left_open": False,
            "resource_limits": {
                "source_json_bytes": source_path.stat().st_size,
                "expected002_json_bytes": expected_path.stat().st_size,
                "whole_file_disassembly": False,
                "process_memory_limit": "bounded Python JSON decode; no disassembly loaded",
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("work/runtime/information-trade-share-20261027-001/native-trade-entry-inputs-002.json"),
    )
    parser.add_argument(
        "--expected002",
        type=Path,
        default=Path("work/runtime/information-trade-source-details-20261027-001/expected-trade-source-details-002.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("work/runtime/information-trade-merchant-state-20261027-001/native-flag-inputs-from-archived-raw-001.json"),
    )
    args = parser.parse_args()
    source = args.source.resolve()
    expected = args.expected002.resolve()
    output = args.output.resolve()
    _require(source.exists(), f"source does not exist: {source}")
    _require(expected.exists(), f"expected002 does not exist: {expected}")
    _require(not output.exists(), f"output already exists: {output}")
    report = build_report(_load(source), _load(expected), source, expected)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(output)
    print(f"nodes={report['counts']['node_count']} passes={report['capture_summary']['passes']}")
    print(f"sha256={_sha256(output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
