"""Capture the extended trade-source raw inputs with bounded RPM only.

The existing country/trade graph reader supplies identity, node keys and the
FRA fullref.  This callback adds fresh 0xc0-byte entry copies, the bounded
capital pointer chain, and a finite raw entry+0x90 list walk.  It never calls a
game function and never translates dynamic names or derives public values.
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

from work.probe_information_current_overextension import probe  # noqa: E402
from work.probe_information_trade_income import read_trade  # noqa: E402


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
MAX_SINGLE_RPM = 64 * 1024
MAX_TOTAL_RPM = 512 * 1024
MAX_EXTENSION_BYTES = 128 * 1024
MAX_NAME_BYTES = 1024
MAX_ITEMS_PER_NODE = 64
MAX_ITEMS_GLOBAL = 256
CAPITAL_DATABASE_RVA = 0x233D8B0
CAPITAL_TABLE_OFFSET = 0x118
CAPITAL_COUNTRY_ANCHOR_OFFSET = 0x14C8
CAPITAL_NODE_IDENTITY_OFFSET = 0xE8
CAPITAL_SCALAR_RVA = 0x233F2F0

STAGE = ROOT / "work/runtime/information-trade-source-details-20261027-001"
PROFILE_PATH = ROOT / "bridge/information/profiles/trade-details-memory-1374-v2.json"
SOURCE_INDEX_PATH = STAGE / "trade-details-source-index-002.json"
EXPECTED_PROFILE_SHA256 = "6f4f248041561b700ca50529e146a9d19272f0b7fab7bbdbe33b0788518e169f"
EXPECTED_SOURCE_INDEX_SHA256 = "50ad236e23c0479c60a04aa7741db99e1f2c33c87e615596e24f826f419ccb6a"


class ExtensionBudgetExceeded(RuntimeError):
    pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _i32(raw: bytes) -> int:
    value = int.from_bytes(raw, "little", signed=False)
    return value - 0x100000000 if value & 0x80000000 else value


def _u64(raw: bytes) -> int:
    if len(raw) != 8:
        raise ValueError("pointer_width_invalid")
    return int.from_bytes(raw, "little", signed=False)


def _pointer(value: int, label: str) -> int:
    if not 0x10000 <= value < 0x7FFFFFFFFFFF:
        raise ValueError(f"pointer_invalid:{label}")
    return value


def _optional_pointer(raw: bytes, label: str) -> int:
    value = _u64(raw)
    if value == 0:
        return 0
    return _pointer(value, label)


def _load_installation_preflight(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise RuntimeError("installation_missing")
    document = json.loads(path.read_text(encoding="utf-8"))
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


def _static_pin() -> dict[str, Any]:
    if not PROFILE_PATH.is_file() or not SOURCE_INDEX_PATH.is_file():
        raise RuntimeError("trade_source_details_profile_or_source_missing")
    profile_sha = _sha256_file(PROFILE_PATH)
    source_sha = _sha256_file(SOURCE_INDEX_PATH)
    if profile_sha != EXPECTED_PROFILE_SHA256:
        raise RuntimeError(f"trade_source_details_profile_sha_mismatch:{profile_sha}")
    if source_sha != EXPECTED_SOURCE_INDEX_SHA256:
        raise RuntimeError(f"trade_source_details_source_index_sha_mismatch:{source_sha}")
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    if profile.get("profile_id") != "trade-details-memory-1374-v2":
        raise RuntimeError("trade_source_details_profile_id_mismatch")
    if len(profile.get("code_guards", [])) != 14:
        raise RuntimeError("trade_source_details_guard_count_mismatch")
    return {
        "status": "observed",
        "profile_id": profile["profile_id"],
        "profile_path": PROFILE_PATH.relative_to(ROOT).as_posix(),
        "profile_sha256": profile_sha,
        "source_index_path": SOURCE_INDEX_PATH.relative_to(ROOT).as_posix(),
        "source_index_sha256": source_sha,
        "guard_count": len(profile["code_guards"]),
        "layout_contract": {
            "entry_size_bytes": ENTRY_SIZE,
            "share_offset": "0x2c",
            "source_offsets": {
                "TP_PROVINCE_POWER": "0x28",
                "TP_SHIP_POWER": "0x1c",
                "MERCHANT_DOWNSTREAM_BONUS": "0x40",
            },
            "capital_scalar_rva": hex(CAPITAL_SCALAR_RVA),
            "dynamic_head_offset": "0x90",
            "dynamic_item_offset": "0x0",
            "dynamic_next_offset": "0x10",
            "dynamic_item_value_offset": "0x34",
            "dynamic_name_object_offset": "0x10",
            "dynamic_name_capacity_offset": "0x18",
            "dynamic_name_heap_pointer_offset": "0x0",
            "dynamic_name_inline_threshold": 16,
            "dynamic_name_max_bytes": MAX_NAME_BYTES,
            "dynamic_max_items_per_node": MAX_ITEMS_PER_NODE,
            "dynamic_max_items_global": MAX_ITEMS_GLOBAL,
            "max_extension_read_bytes_per_pass": MAX_EXTENSION_BYTES,
        },
        "dynamic_name_semantics": "raw lookup-key candidate; no locale translation or display-template derivation",
    }


class ExtensionReader:
    def __init__(self, reader: Any):
        self.reader = reader
        self.bytes_requested = 0
        self.calls = 0
        self.budget = MAX_EXTENSION_BYTES

    def read(self, address: int, size: int, label: str) -> bytes:
        if size <= 0 or size > MAX_SINGLE_RPM:
            raise ValueError(f"extension_read_size_invalid:{size}")
        if self.bytes_requested + size > self.budget:
            raise ExtensionBudgetExceeded(
                f"extension_budget:{self.bytes_requested}+{size}>{self.budget}"
            )
        raw = self.reader.read(address, size, "reference.trade_source_details." + label)
        if len(raw) != size:
            raise ValueError(f"extension_short_read:{label}")
        self.bytes_requested += size
        self.calls += 1
        return raw

    def pointer(self, address: int, label: str) -> tuple[int, str]:
        raw = self.read(address, 8, label)
        return _pointer(_u64(raw), label), raw.hex()


def _source_inputs(entry_raw: bytes) -> dict[str, dict[str, Any]]:
    definitions = (
        ("TP_PROVINCE_POWER", 0x28, lambda value: value != 0),
        ("TP_SHIP_POWER", 0x1C, lambda value: value != 0),
        ("MERCHANT_DOWNSTREAM_BONUS", 0x40, lambda value: value > 0),
    )
    result = {}
    for key, offset, predicate in definitions:
        raw = entry_raw[offset:offset + 4]
        value = _i32(raw)
        result[key] = {
            "raw": value,
            "raw_hex": raw.hex(),
            "included_by_static_condition": bool(predicate(value)),
        }
    return result


def _capture_capital(extension: ExtensionReader, base: int, slot: int, node_pointers: list[dict[str, Any]]) -> dict[str, Any]:
    root, root_hex = extension.pointer(base + CAPITAL_DATABASE_RVA, "capital.database_root")
    table, table_hex = extension.pointer(root + CAPITAL_TABLE_OFFSET, "capital.country_table")
    selected_address = table + slot * 8
    selected, selected_hex = extension.pointer(selected_address, "capital.selected_country")
    anchor, anchor_hex = extension.pointer(selected + CAPITAL_COUNTRY_ANCHOR_OFFSET, "capital.country_anchor")
    node_identity, node_identity_hex = extension.pointer(anchor + CAPITAL_NODE_IDENTITY_OFFSET, "capital.anchor_node_identity")
    scalar_raw = extension.read(base + CAPITAL_SCALAR_RVA, 4, "capital.scalar")
    scalar = _i32(scalar_raw)
    conditions = {}
    for node in node_pointers:
        node_pointer = _pointer(int(node["runtime_pointer"], 0), f"capital.node.{node['node_id']}")
        conditions[node["node_id"]] = {
            "anchor_node_identity_raw_hex": node_identity_hex,
            "node_runtime_pointer_raw_hex": int(node_pointer).to_bytes(8, "little").hex(),
            "matches": node_identity == node_pointer,
        }
    return {
        "database_root_raw_hex": root_hex,
        "country_table_raw_hex": table_hex,
        "country_table_slot": slot,
        "selected_country_raw_hex": selected_hex,
        "country_anchor_raw_hex": anchor_hex,
        "anchor_node_identity_raw_hex": node_identity_hex,
        "scalar_raw": scalar,
        "scalar_raw_hex": scalar_raw.hex(),
        "conditions_by_node": conditions,
        "raw_only": True,
        "unit_or_display_value_not_derived": True,
    }


def _capture_dynamic(extension: ExtensionReader, entry_address: int, node_id: str, state: dict[str, Any]) -> dict[str, Any]:
    if state["budget_exhausted"]:
        return {
            "status": "unknown",
            "reason": "extension_budget_exhausted_before_node",
            "head_raw_hex": None,
            "items": [],
            "items_retracted": True,
        }
    try:
        head_raw = extension.read(entry_address + 0x90, 8, f"dynamic.{node_id}.head")
        head_hex = head_raw.hex()
        head = _optional_pointer(head_raw, f"dynamic.{node_id}.head")
        if head == 0:
            return {
                "status": "empty",
                "reason": "head_null",
                "head_raw_hex": head_hex,
                "items": [],
                "items_retracted": False,
            }
        pointer = head
        seen: set[int] = set()
        pending: list[dict[str, Any]] = []
        while pointer:
            if len(pending) >= MAX_ITEMS_PER_NODE:
                raise ValueError("per_node_item_cap_exceeded")
            if len(state["all_items"]) + len(pending) >= MAX_ITEMS_GLOBAL:
                raise ValueError("global_item_cap_exceeded")
            if pointer in seen:
                raise ValueError("dynamic_link_cycle")
            seen.add(pointer)
            item, item_hex = extension.pointer(pointer, f"dynamic.{node_id}.link_item")
            value_raw = extension.read(item + 0x34, 4, f"dynamic.{node_id}.item_value")
            name_object = item + 0x10
            capacity_raw = extension.read(name_object + 0x18, 8, f"dynamic.{node_id}.name_capacity")
            capacity = _u64(capacity_raw)
            heap_pointer_hex = None
            if capacity < 0x10:
                name_pointer = name_object
                name_pointer_hex = int(name_pointer).to_bytes(8, "little").hex()
                pointer_mode = "inline_object_base"
            else:
                name_pointer, heap_pointer_hex = extension.pointer(name_object, f"dynamic.{node_id}.name_heap_pointer")
                name_pointer_hex = heap_pointer_hex
                pointer_mode = "heap_pointer_at_object_base"
            name_probe = extension.read(name_pointer, MAX_NAME_BYTES, f"dynamic.{node_id}.name_bytes")
            nul = name_probe.find(b"\0")
            if nul < 0:
                raise ValueError("dynamic_name_nul_not_found_within_1024")
            next_raw = extension.read(pointer + 0x10, 8, f"dynamic.{node_id}.next")
            next_hex = next_raw.hex()
            next_pointer = _optional_pointer(next_raw, f"dynamic.{node_id}.next")
            pending.append({
                "link_pointer_raw_hex": int(pointer).to_bytes(8, "little").hex(),
                "item_pointer_raw_hex": item_hex,
                "item_value_raw": _i32(value_raw),
                "item_value_raw_hex": value_raw.hex(),
                "name_object_offset": "0x10",
                "name_capacity_raw_hex": capacity_raw.hex(),
                "name_capacity": capacity,
                "name_pointer_raw_hex": name_pointer_hex,
                "name_pointer_mode": pointer_mode,
                "name_raw_hex": name_probe[:nul + 1].hex(),
                "name_terminated": True,
                "next_pointer_raw_hex": next_hex,
            })
            pointer = next_pointer
        state["all_items"].extend(pending)
        return {
            "status": "observed",
            "reason": "nonempty_raw_chain",
            "head_raw_hex": head_hex,
            "items": pending,
            "items_retracted": False,
        }
    except ExtensionBudgetExceeded as exc:
        state["budget_exhausted"] = True
        return {
            "status": "unknown",
            "reason": str(exc),
            "head_raw_hex": None,
            "items": [],
            "items_retracted": True,
        }
    except Exception as exc:
        return {
            "status": "unknown",
            "reason": f"{type(exc).__name__}:{exc}",
            "head_raw_hex": None,
            "items": [],
            "items_retracted": True,
        }


def read_source_details(reader: Any, base: int, country_pointer: int) -> dict[str, Any]:
    if not isinstance(country_pointer, int) or isinstance(country_pointer, bool):
        raise ValueError("country_pointer_must_be_integer")
    graph = read_trade(reader, base, country_pointer)
    nodes = graph.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("trade_graph_nodes_missing")
    true_nodes = [node for node in nodes if int(node["predicate_rva"], 0) == TRUE_PREDICATE_RVA]
    false_nodes = [node for node in nodes if int(node["predicate_rva"], 0) == FALSE_PREDICATE_RVA]
    if len(true_nodes) != EXPECTED_TRUE_NODES:
        raise ValueError(f"true_trade_node_count:{len(true_nodes)}")
    if any(node.get("node_id") != "Null" for node in false_nodes):
        raise ValueError("false_predicate_non_null_definition")

    extension = ExtensionReader(reader)
    entries: list[dict[str, Any]] = []
    for node in true_nodes:
        entry_address = _pointer(int(node["entry_address"], 0), f"entry.{node['node_id']}")
        entry_raw = extension.read(entry_address, ENTRY_SIZE, f"entry_full.{node['node_id']}")
        entries.append({
            "node": node,
            "entry_address": entry_address,
            "entry_raw": entry_raw,
            "entry_raw_hex": entry_raw.hex(),
        })

    slot = graph.get("country_slot")
    if not isinstance(slot, int) or slot < 0:
        raise ValueError("country_slot_missing")
    capital = _capture_capital(extension, base, slot, [item["node"] for item in entries])
    state = {"all_items": [], "budget_exhausted": False}
    output_nodes = []
    for item in entries:
        node = item["node"]
        dynamic = _capture_dynamic(extension, item["entry_address"], node["node_id"], state)
        output_nodes.append({
            "node_id": node["node_id"],
            "predicate_rva": node["predicate_rva"],
            "runtime_pointer": node["runtime_pointer"],
            "entry_address": node["entry_address"],
            "entry_raw_hex": item["entry_raw_hex"],
            "entry_size_bytes": ENTRY_SIZE,
            "share_raw": _i32(item["entry_raw"][0x2C:0x30]),
            "share_raw_hex": item["entry_raw"][0x2C:0x30].hex(),
            "source_inputs": _source_inputs(item["entry_raw"]),
            "capital_condition": capital["conditions_by_node"][node["node_id"]],
            "dynamic_sources": dynamic,
        })
    return {
        "module_base": hex(base),
        "country": "FRA",
        "country_pointer_raw_hex": int(country_pointer).to_bytes(8, "little").hex(),
        "country_fullref_raw_hex": graph["country_reference_raw_hex"],
        "country_slot": slot,
        "nodes": graph["nodes"],
        "trade_source_nodes": output_nodes,
        "skipped_false_nodes": [{
            "node_id": node.get("node_id"),
            "predicate_rva": node.get("predicate_rva"),
            "entry_read": False,
        } for node in false_nodes],
        "true_node_count": len(output_nodes),
        "false_node_count": len(false_nodes),
        "entry_read_bytes": len(output_nodes) * ENTRY_SIZE,
        "capital_context": capital,
        "extension_budget": {
            "max_bytes": MAX_EXTENSION_BYTES,
            "bytes_requested": extension.bytes_requested,
            "rpm_calls": extension.calls,
            "dynamic_items_completed": len(state["all_items"]),
            "budget_exhausted": state["budget_exhausted"],
            "max_name_bytes": MAX_NAME_BYTES,
            "max_items_per_node": MAX_ITEMS_PER_NODE,
            "max_items_global": MAX_ITEMS_GLOBAL,
        },
        "raw_input_semantics": "Fresh raw 0xc0 entries, raw capital pointer/scalar chain, and bounded raw dynamic link/name bytes; no public value, unit normalization, or locale translation.",
    }


def _post_validate(report: dict[str, Any]) -> None:
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
    passes = report.get("trade_source_details_inputs")
    if not isinstance(passes, list) or len(passes) != 2:
        failures.append("two_passes")
        passes = []
    for index, record in enumerate(passes):
        date = record.get("date") if isinstance(record, dict) else None
        date_raw = date.get("value") if isinstance(date, dict) else None
        if date_raw != EXPECTED_DATE:
            failures.append(f"date_pass_{index}:{date_raw!r}")
        nodes = record.get("trade_source_nodes") if isinstance(record, dict) else None
        if not isinstance(nodes, list) or len(nodes) != EXPECTED_TRUE_NODES:
            failures.append(f"true_nodes_pass_{index}")
        else:
            bad = [node.get("node_id") for node in nodes if len(node.get("entry_raw_hex", "")) != ENTRY_SIZE * 2]
            if bad:
                failures.append(f"entry_hex_pass_{index}:{bad[:3]}")
        budget = record.get("extension_budget", {}) if isinstance(record, dict) else {}
        if budget.get("bytes_requested", MAX_EXTENSION_BYTES + 1) > MAX_EXTENSION_BYTES:
            failures.append(f"extension_budget_pass_{index}")
    if failures:
        report["status"] = "identity_or_contract_mismatch"
        report["completed"] = False
        report.setdefault("errors", []).append({"stage": "strict_trade_source_details_postcheck", "error": ";".join(failures)})
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


def _repair_empty_heads(source_path: Path, output_path: Path) -> int:
    """Repair only the zero-head interpretation from an existing raw report.

    This is intentionally a deterministic post-capture repair.  It never opens
    a process and never changes the captured entry bytes or identity metadata.
    """
    if output_path.exists():
        raise RuntimeError("refusing_to_overwrite_output")
    raw = source_path.read_bytes()
    report = json.loads(raw.decode("utf-8"))
    if report.get("status") != "observed" or report.get("completed") is not True:
        raise RuntimeError("repair_source_not_completed")
    passes = report.get("trade_source_details_inputs")
    if not isinstance(passes, list) or len(passes) != 2:
        raise RuntimeError("repair_source_two_passes_missing")
    repaired = 0
    for record in passes:
        nodes = record.get("trade_source_nodes")
        if not isinstance(nodes, list):
            raise RuntimeError("repair_source_nodes_missing")
        for node in nodes:
            entry_raw = bytes.fromhex(node.get("entry_raw_hex", ""))
            if len(entry_raw) != ENTRY_SIZE:
                raise RuntimeError("repair_source_entry_width_invalid")
            head_raw = entry_raw[0x90:0x98]
            if int.from_bytes(head_raw, "little") == 0:
                node["dynamic_sources"] = {
                    "status": "empty",
                    "reason": "head_null",
                    "head_raw_hex": head_raw.hex(),
                    "items": [],
                    "items_retracted": False,
                }
                repaired += 1
        budget = record.get("extension_budget")
        if isinstance(budget, dict):
            budget["dynamic_items_completed"] = 0
            budget["budget_exhausted"] = False
    report["probe"] = "information-independent-trade-source-details-runtime-repair"
    report["probe_script"] = str(Path(__file__).resolve())
    report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    report["probe_repair"] = {
        "source_path": source_path.relative_to(ROOT).as_posix(),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "repair_kind": "zero_head_pointer_is_empty_list",
        "repaired_node_records": repaired,
        "new_rpm_sample": False,
        "identity_date_handle_source_preserved": True,
        "reason": "The initial capture applied the nonzero pointer guard before accepting a null list head; raw entry+0x90 bytes are authoritative for the empty-head branch.",
    }
    _post_validate(report)
    report.setdefault("access_summary", {})["repaired_without_new_rpm"] = True
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return repaired


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repair-from", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing_to_overwrite_output")
    if args.repair_from is not None:
        repair_source = args.repair_from if args.repair_from.is_absolute() else ROOT / args.repair_from
        repair_output = args.output if args.output.is_absolute() else ROOT / args.output
        repaired = _repair_empty_heads(repair_source, repair_output)
        print(json.dumps({"status": "observed", "completed": True, "repaired_node_records": repaired, "new_rpm_sample": False}, ensure_ascii=False))
        return 0
    if args.installation is None:
        parser.error("--installation is required unless --repair-from is used")
    _load_installation_preflight(args.installation)
    static_pin = _static_pin()
    report = probe(args.installation, field="trade_source_details", input_reader=read_source_details)
    report["probe"] = "information-independent-trade-source-details-runtime"
    report["probe_script"] = str(Path(__file__).resolve())
    report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    report["schema"] = "information_independent_trade_source_details_inputs.v1"
    report["field"] = "trade_source_details"
    report["request"]["fields"] = ["trade_source_details"]
    report["request"]["country_locator_fields"] = ["stability"]
    report["locator_dependency"] = {
        "underlying_probe_field": "stability",
        "purpose": "country/fullref/node locator only",
        "not_a_trade_source_guard": True,
    }
    report["trade_source_details_static_contract_guard"] = static_pin
    report["capture_contract"] = {
        "reader": "read_trade plus fresh bounded 0xc0 entries, capital pointer/scalar chain, and entry+0x90 dynamic raw walks",
        "passes": 2,
        "true_predicate_rva": hex(TRUE_PREDICATE_RVA),
        "false_predicate_rva": hex(FALSE_PREDICATE_RVA),
        "expected_true_nodes_per_pass": EXPECTED_TRUE_NODES,
        "entry_size_bytes": ENTRY_SIZE,
        "max_single_rpm_bytes": MAX_SINGLE_RPM,
        "max_total_rpm_bytes": MAX_TOTAL_RPM,
        "max_extension_read_bytes_per_pass": MAX_EXTENSION_BYTES,
        "dynamic_max_name_bytes": MAX_NAME_BYTES,
        "dynamic_max_items_per_node": MAX_ITEMS_PER_NODE,
        "dynamic_max_items_global": MAX_ITEMS_GLOBAL,
        "raw_only": True,
        "native_function_invoked": False,
        "target_memory_writes": False,
        "dynamic_name_translation": False,
    }
    _post_validate(report)
    report["access_summary"] = {
        "rpm_bytes_requested": report.get("access", {}).get("rpm_bytes_requested"),
        "rpm_calls": report.get("access", {}).get("rpm_calls"),
        "handle_close": report.get("cleanup", {}).get("handle_close"),
        "true_nodes_per_pass": EXPECTED_TRUE_NODES,
        "passes": len(report.get("trade_source_details_inputs", [])),
        "extension_bytes_per_pass": [
            item.get("extension_budget", {}).get("bytes_requested")
            for item in report.get("trade_source_details_inputs", [])
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({
        "status": report.get("status"),
        "completed": report.get("completed"),
        "bytes": report.get("access_summary", {}).get("rpm_bytes_requested"),
        "calls": report.get("access_summary", {}).get("rpm_calls"),
        "nodes_per_pass": EXPECTED_TRUE_NODES,
        "passes": report.get("access_summary", {}).get("passes"),
        "extension_bytes_per_pass": report.get("access_summary", {}).get("extension_bytes_per_pass"),
        "handle_closed": report.get("access_summary", {}).get("handle_close", {}).get("closed"),
        "errors": report.get("errors"),
    }, ensure_ascii=False))
    return 0 if report.get("completed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
