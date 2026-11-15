"""Capture complete native trade-node entries with the existing bounded RPM seams.

This probe deliberately keeps the established country/trade graph reader as the
identity and topology source.  It adds one bounded 0xc0-byte read at each
validated true trade-node entry and never invokes a native game function.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.probe_information_current_overextension import probe
from work.probe_information_trade_income import read_trade


EXPECTED_PID = 31460
EXPECTED_CREATION_FILETIME = 134374886912306555
EXPECTED_SESSION_ID = "31460-1dd653f69242d7b"
EXPECTED_DATE = 56557728
EXPECTED_VERSION = "1.37.4"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_EXPERIMENT = "diplomacy-observer-20261026-information-battle-v27-002"
TRUE_PREDICATE_RVA = 0x8F440
FALSE_PREDICATE_RVA = 0x8F450
ENTRY_SIZE = 0xC0
EXPECTED_TRUE_NODES = 80


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_installation_preflight(path: Path) -> dict[str, Any]:
    """Reject a different installation before opening a process handle."""
    if not path.is_file():
        raise RuntimeError("installation_missing")
    with path.open("r", encoding="utf-8") as stream:
        document = json.load(stream)
    expected = {
        "pid": EXPECTED_PID,
        "creation_filetime": EXPECTED_CREATION_FILETIME,
        "session_id": EXPECTED_SESSION_ID,
        "game_sha256": EXPECTED_EXE_SHA256,
        "experiment_id": EXPECTED_EXPERIMENT,
    }
    mismatches = [
        f"{key}={document.get(key)!r}"
        for key, value in expected.items()
        if document.get(key) != value
    ]
    if mismatches:
        raise RuntimeError("installation_identity_mismatch:" + ",".join(mismatches))
    return document


def read_entries(reader: Any, base: int, country_pointer: int) -> dict[str, Any]:
    """Read the old graph, then add full entries only for true predicates."""
    if not isinstance(country_pointer, int) or isinstance(country_pointer, bool):
        raise ValueError("country_pointer_must_be_integer")

    # The callback receives the resolved country pointer, not a country tag.
    # read_trade performs the FRA fullref/tag/slot checks against that pointer.
    graph = read_trade(reader, base, country_pointer)
    nodes = graph.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("trade_graph_nodes_missing")

    true_nodes: list[dict[str, Any]] = []
    skipped_false_nodes: list[dict[str, Any]] = []
    for node in nodes:
        try:
            predicate_rva = int(node["predicate_rva"], 0)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("trade_predicate_rva_invalid") from exc
        if predicate_rva == TRUE_PREDICATE_RVA:
            true_nodes.append(node)
        elif predicate_rva == FALSE_PREDICATE_RVA:
            if node.get("node_id") != "Null":
                raise ValueError("false_predicate_non_null_definition")
            skipped_false_nodes.append({
                "node_id": node.get("node_id"),
                "predicate_rva": node.get("predicate_rva"),
                "definition_pointer": node.get("definition_pointer"),
                "runtime_pointer": node.get("runtime_pointer"),
                "entry_address": node.get("entry_address"),
                "entry_read": False,
            })
        else:
            raise ValueError(f"unexpected_trade_predicate:{node.get('predicate_rva')}")

    if len(true_nodes) != EXPECTED_TRUE_NODES:
        raise ValueError(f"true_trade_node_count:{len(true_nodes)}")

    for node in true_nodes:
        try:
            entry_address = int(node["entry_address"], 0)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("validated_entry_address_invalid") from exc
        raw = reader.read(
            entry_address,
            ENTRY_SIZE,
            f"reference.trade.entry_full.{node['node_id']}",
        )
        if len(raw) != ENTRY_SIZE:
            raise ValueError("trade_entry_short_read")
        node["entry_raw_hex"] = raw.hex()
        node["entry_size_bytes"] = ENTRY_SIZE
        node["entry_span_hex"] = hex(ENTRY_SIZE)
        node["entry_read"] = True

    # Keep the full old graph under ``nodes`` and provide a focused true-node
    # view for consumers that need only the new 192-byte payloads.
    graph["trade_entry_nodes"] = [dict(node) for node in true_nodes]
    graph["skipped_false_nodes"] = skipped_false_nodes
    graph["true_node_count"] = len(true_nodes)
    graph["false_node_count"] = len(skipped_false_nodes)
    graph["fullref_slot"] = graph.get("country_slot")
    graph["entry_read_bytes"] = len(true_nodes) * ENTRY_SIZE
    graph["entry_capture_contract"] = {
        "entry_offset_from_validated_country_table": "country_slot * 0xc0",
        "entry_size_bytes": ENTRY_SIZE,
        "single_read_limit_bytes": 65536,
        "total_rpm_limit_bytes": 512 * 1024,
        "true_predicate_rva": hex(TRUE_PREDICATE_RVA),
        "false_predicate_rva": hex(FALSE_PREDICATE_RVA),
        "false_definition_action": "skip_entry_read_only_Null",
        "unexpected_predicate_action": "reject_capture",
        "raw_only": True,
    }
    graph["raw_input_semantics"] = (
        "Complete old trade graph plus raw 0xc0 entry bytes for each true "
        "predicate node; no share/source/GUI calculation or equivalence claim."
    )
    return graph


def _post_validate(report: dict[str, Any]) -> None:
    """Apply the fixed date/session/node-count contract after the two passes."""
    failures: list[str] = []
    identity = report.get("identity") if isinstance(report.get("identity"), dict) else {}
    checks = {
        "pid": identity.get("installation_pid") == EXPECTED_PID,
        "creation_filetime": identity.get("installation_creation_filetime") == EXPECTED_CREATION_FILETIME,
        "session_id": identity.get("installation_session_id") == EXPECTED_SESSION_ID,
        "process_creation": identity.get("process_creation_matches_installation") is True,
        "binding": identity.get("binding_verified") is True,
    }
    failures.extend(key for key, ok in checks.items() if not ok)
    passes = report.get("trade_entries_inputs")
    if not isinstance(passes, list) or len(passes) != 2:
        failures.append("two_passes")
        passes = []
    for index, record in enumerate(passes):
        date = record.get("date") if isinstance(record, dict) else None
        date_raw = date.get("value") if isinstance(date, dict) else None
        if date_raw != EXPECTED_DATE:
            failures.append(f"date_pass_{index}:{date_raw!r}")
        nodes = record.get("trade_entry_nodes") if isinstance(record, dict) else None
        if not isinstance(nodes, list) or len(nodes) != EXPECTED_TRUE_NODES:
            failures.append(f"true_nodes_pass_{index}")
        else:
            bad = [node.get("node_id") for node in nodes if len(node.get("entry_raw_hex", "")) != ENTRY_SIZE * 2]
            if bad:
                failures.append(f"entry_hex_pass_{index}:{bad[:3]}")
    if failures:
        report["status"] = "identity_or_contract_mismatch"
        report["completed"] = False
        report.setdefault("errors", []).append({
            "stage": "strict_trade_entry_postcheck",
            "error": ";".join(failures),
        })
    report["strict_identity_contract"] = {
        "installation_experiment": EXPECTED_EXPERIMENT,
        "pid": EXPECTED_PID,
        "creation_filetime": EXPECTED_CREATION_FILETIME,
        "session_id": EXPECTED_SESSION_ID,
        "game_date_raw": EXPECTED_DATE,
        "game_version": EXPECTED_VERSION,
        "exe_sha256": EXPECTED_EXE_SHA256,
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing_to_overwrite_output")
    _load_installation_preflight(args.installation)

    report = probe(args.installation, field="trade_entries", input_reader=read_entries)
    report["probe"] = "information-independent-trade-entry-runtime"
    report["probe_script"] = str(Path(__file__).resolve())
    report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    report["schema"] = "information_independent_trade_entry_inputs.v1"
    report["field"] = "trade_entries"
    report["capture_contract"] = {
        "reader": "read_trade plus bounded full 0xc0-byte reads",
        "passes": 2,
        "true_predicate_rva": hex(TRUE_PREDICATE_RVA),
        "false_predicate_rva": hex(FALSE_PREDICATE_RVA),
        "expected_true_nodes_per_pass": EXPECTED_TRUE_NODES,
        "entry_size_bytes": ENTRY_SIZE,
        "max_single_rpm_bytes": 65536,
        "max_total_rpm_bytes": 512 * 1024,
        "raw_only": True,
        "native_function_invoked": False,
        "target_memory_writes": False,
    }
    _post_validate(report)
    report["access_summary"] = {
        "rpm_bytes_requested": report.get("access", {}).get("rpm_bytes_requested"),
        "rpm_calls": report.get("access", {}).get("rpm_calls"),
        "handle_close": report.get("cleanup", {}).get("handle_close"),
        "true_nodes_per_pass": EXPECTED_TRUE_NODES,
        "passes": len(report.get("trade_entries_inputs", [])),
    }

    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({
        "status": report.get("status"),
        "completed": report.get("completed"),
        "calls": report.get("access_summary", {}).get("rpm_calls"),
        "bytes": report.get("access_summary", {}).get("rpm_bytes_requested"),
        "nodes_per_pass": EXPECTED_TRUE_NODES,
        "passes": report.get("access_summary", {}).get("passes"),
        "handle_closed": report.get("access_summary", {}).get("handle_close", {}).get("closed"),
        "errors": report.get("errors"),
    }, ensure_ascii=False))
    return 0 if report.get("completed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
