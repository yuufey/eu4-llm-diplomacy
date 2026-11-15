"""Bounded raw probe for the Batch-46 transfer-detail tail.

The v2 report already contains the complete 0xc0-byte entries, capital data,
and the old entry+0x90 contract.  This probe reuses that frozen raw seed and
reads only the missing entry+0x60/+0x78 chains plus the country-table fullref
bindings.  It also rechecks the three chain heads and shares the 128 KiB,
64-per-node, 256-global extension budget.  No native function or game write is
performed.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
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
TAIL_TO_OFFSET = 0x60
TAIL_FROM_OFFSET = 0x78
DYNAMIC_OFFSET = 0x90
TAIL_ELEMENT_READ_BYTES = 0x20
CAPITAL_DATABASE_RVA = 0x233D8B0
CAPITAL_TABLE_OFFSET = 0x118
COUNTRY_FULLREF_OFFSET = 0x20
MAX_COUNTRY_SLOT = 4095

STAGE = ROOT / "work/runtime/information-trade-source-details-20261027-001"
PROFILE_PATH = ROOT / "bridge/information/profiles/trade-details-memory-1374-v3.json"
SOURCE_INDEX_PATH = STAGE / "trade-details-source-index-003.json"
SEED_PATH = STAGE / "native-trade-source-details-inputs-002.json"
EXPECTED_PROFILE_SHA256 = "e5df6c617090d1df63eaf03d88a9d4716667548f36af9f1e1c24be2b71b06cb1"
EXPECTED_SOURCE_INDEX_SHA256 = "43f7f699c61ea08f7e298aeda210368c296df6d6addeb5db65ac7401f52e7674"
EXPECTED_SEED_SHA256 = "46d716e9302062382ce0af56d4f33977296d5bd35978f8d33666b18a04878a83"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


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
    return 0 if value == 0 else _pointer(value, label)


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


def _load_seed() -> tuple[dict[str, Any], dict[str, Any]]:
    if not SEED_PATH.is_file() or digest(SEED_PATH) != EXPECTED_SEED_SHA256:
        raise RuntimeError("v2_seed_sha_mismatch")
    document = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    if document.get("status") != "observed" or document.get("completed") is not True:
        raise RuntimeError("v2_seed_not_complete")
    passes = document.get("trade_source_details_inputs")
    if not isinstance(passes, list) or len(passes) != 2 or passes[0] != passes[1]:
        raise RuntimeError("v2_seed_passes_not_identical")
    first = passes[0]
    nodes = first.get("trade_source_nodes")
    if not isinstance(nodes, list) or len(nodes) != EXPECTED_TRUE_NODES:
        raise RuntimeError("v2_seed_node_count_mismatch")
    return document, {node["node_id"]: node for node in nodes}


def _static_pin() -> dict[str, Any]:
    if not PROFILE_PATH.is_file() or not SOURCE_INDEX_PATH.is_file():
        raise RuntimeError("v3_profile_or_source_missing")
    profile_sha = digest(PROFILE_PATH)
    source_sha = digest(SOURCE_INDEX_PATH)
    if profile_sha != EXPECTED_PROFILE_SHA256:
        raise RuntimeError(f"v3_profile_sha_mismatch:{profile_sha}")
    if source_sha != EXPECTED_SOURCE_INDEX_SHA256:
        raise RuntimeError(f"v3_source_index_sha_mismatch:{source_sha}")
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    if profile.get("profile_id") != "trade-details-memory-1374-v3":
        raise RuntimeError("v3_profile_id_mismatch")
    if len(profile.get("code_guards", [])) != 18:
        raise RuntimeError("v3_guard_count_mismatch")
    return {
        "status": "observed",
        "profile_id": profile["profile_id"],
        "profile_path": PROFILE_PATH.relative_to(ROOT).as_posix(),
        "profile_sha256": profile_sha,
        "source_index_path": SOURCE_INDEX_PATH.relative_to(ROOT).as_posix(),
        "source_index_sha256": source_sha,
        "guard_count": len(profile["code_guards"]),
        "tail_layout": profile["layout"]["native_tail"],
    }


class ExtensionBudgetExceeded(RuntimeError):
    pass


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
        raw = self.reader.read(address, size, "reference.trade_source_details_v3." + label)
        if len(raw) != size:
            raise ValueError(f"extension_short_read:{label}")
        self.bytes_requested += size
        self.calls += 1
        return raw

    def pointer(self, address: int, label: str) -> tuple[int, str]:
        raw = self.read(address, 8, label)
        return _pointer(_u64(raw), label), raw.hex()


def _read_country_table(extension: ExtensionReader, base: int, slot: int, expected_fullref_hex: str) -> dict[str, Any]:
    root, root_hex = extension.pointer(base + CAPITAL_DATABASE_RVA, "country_table.database_root")
    table, table_hex = extension.pointer(root + CAPITAL_TABLE_OFFSET, "country_table.table")
    selected, selected_hex = extension.pointer(table + slot * 8, "country_table.selected_country")
    selected_fullref = extension.read(selected + COUNTRY_FULLREF_OFFSET, 8, "country_table.selected_fullref")
    if selected_fullref.hex() != expected_fullref_hex:
        raise ValueError("country_table_selected_fullref_mismatch")
    return {
        "database_root_raw_hex": root_hex,
        "country_table_raw_hex": table_hex,
        "selected_slot": slot,
        "selected_country_raw_hex": selected_hex,
        "selected_country_fullref_raw_hex": selected_fullref.hex(),
        "selected_fullref_matches_locator": True,
    }


def _country_binding(extension: ExtensionReader, table: int, fullref: bytes, label: str) -> dict[str, Any]:
    if len(fullref) != 8:
        raise ValueError("tail_fullref_width_invalid")
    slot = int.from_bytes(fullref[4:6], "little", signed=True)
    result: dict[str, Any] = {
        "element_fullref_raw_hex": fullref.hex(),
        "element_fullref_slot": slot,
        "max_country_slot_for_read": MAX_COUNTRY_SLOT,
        "country_fullref_matches": False,
        "country_tag": None,
        "country_tag_raw_hex": None,
    }
    if not 0 <= slot <= MAX_COUNTRY_SLOT:
        result["status"] = "unknown"
        result["reason"] = "fullref_slot_out_of_bounded_read_range"
        return result
    country, country_hex = extension.pointer(table + slot * 8, f"{label}.country_table_slot")
    country_fullref = extension.read(country + COUNTRY_FULLREF_OFFSET, 8, f"{label}.country_fullref")
    result["country_pointer_raw_hex"] = country_hex
    result["country_object_fullref_raw_hex"] = country_fullref.hex()
    result["country_fullref_matches"] = country_fullref == fullref
    if country_fullref == fullref:
        tag_raw = fullref[:4]
        result["country_tag_raw_hex"] = tag_raw.hex()
        if tag_raw[3] == 0 and re.fullmatch(rb"[A-Z]{3}", tag_raw[:3]):
            result["country_tag"] = tag_raw[:3].decode("ascii")
            result["status"] = "matched"
        else:
            result["status"] = "matched_tag_unresolved"
            result["reason"] = "fullref_low32_not_ascii_three_letter_tag"
    else:
        result["status"] = "mismatch"
        result["reason"] = "country_table_object_fullref_differed"
    return result


def _capture_tail_chain(
    extension: ExtensionReader,
    entry_address: int,
    entry_head_offset: int,
    direction: str,
    native_key: str,
    table: int,
    state: dict[str, Any],
    expected_head_hex: str,
    node_id: str,
) -> dict[str, Any]:
    prefix = f"tail.{node_id}.{direction}"
    head_raw = extension.read(entry_address + entry_head_offset, 8, f"{prefix}.container")
    if head_raw.hex() != expected_head_hex:
        raise ValueError(f"seed_head_mismatch:{node_id}:{hex(entry_head_offset)}")
    # B5DCD0 receives R8=&entry[offset].  Its first instruction dereferences
    # that field once, so the field value itself is the first element pointer;
    # there is no second container-object dereference here.
    first = _optional_pointer(head_raw, f"{prefix}.head_element")
    base_result = {
        "direction": direction,
        "native_key": native_key,
        "entry_container_offset": hex(entry_head_offset),
        "container_pointer_raw_hex": head_raw.hex(),
        "value_unit": "trade_power",
        "value_scale": 1000,
        "raw_sign_is_direction": False,
        "items": [],
        "items_retracted": False,
    }
    if first == 0:
        base_result.update(status="empty", reason="container_null")
        return base_result
    base_result["head_element_pointer_raw_hex"] = head_raw.hex()
    pointer = first
    seen: set[int] = set()
    pending: list[dict[str, Any]] = []
    while pointer:
        if len(pending) >= MAX_ITEMS_PER_NODE:
            raise ValueError("tail_per_node_item_cap_exceeded")
        if state["item_count"] + len(pending) >= MAX_ITEMS_GLOBAL:
            raise ValueError("tail_global_item_cap_exceeded")
        if pointer in seen:
            raise ValueError("tail_link_cycle")
        seen.add(pointer)
        raw = extension.read(pointer, TAIL_ELEMENT_READ_BYTES, f"{prefix}.element")
        fullref = raw[0:8]
        value_raw = raw[0x08:0x0C]
        next_raw = raw[0x18:0x20]
        pending.append({
            "element_pointer_raw_hex": pointer.to_bytes(8, "little").hex(),
            "fullref_raw_hex": fullref.hex(),
            "value_raw": _i32(value_raw),
            "value_raw_hex": value_raw.hex(),
            "next_pointer_raw_hex": next_raw.hex(),
            "country_binding": _country_binding(extension, table, fullref, f"{prefix}.element"),
        })
        pointer = _optional_pointer(next_raw, f"{prefix}.next")
    state["item_count"] += len(pending)
    base_result.update(status="observed", reason="nonempty_raw_chain", items=pending)
    return base_result


def _capture_dynamic_chain(
    extension: ExtensionReader,
    entry_address: int,
    node_id: str,
    state: dict[str, Any],
    expected_head_hex: str,
) -> dict[str, Any]:
    prefix = f"dynamic.{node_id}"
    head_raw = extension.read(entry_address + DYNAMIC_OFFSET, 8, f"{prefix}.head")
    if head_raw.hex() != expected_head_hex:
        raise ValueError(f"seed_head_mismatch:{node_id}:0x90")
    head = _optional_pointer(head_raw, f"{prefix}.head")
    result = {
        "status": "empty" if head == 0 else "observed",
        "reason": "head_null" if head == 0 else "nonempty_raw_chain",
        "head_raw_hex": head_raw.hex(),
        "items": [],
        "items_retracted": False,
    }
    if head == 0:
        return result
    pointer = head
    seen: set[int] = set()
    pending: list[dict[str, Any]] = []
    while pointer:
        if len(pending) >= MAX_ITEMS_PER_NODE:
            raise ValueError("dynamic_per_node_item_cap_exceeded")
        if state["item_count"] + len(pending) >= MAX_ITEMS_GLOBAL:
            raise ValueError("dynamic_global_item_cap_exceeded")
        if pointer in seen:
            raise ValueError("dynamic_link_cycle")
        seen.add(pointer)
        item, item_hex = extension.pointer(pointer, f"{prefix}.link_item")
        value_raw = extension.read(item + 0x34, 4, f"{prefix}.item_value")
        name_object = item + 0x10
        capacity_raw = extension.read(name_object + 0x18, 8, f"{prefix}.name_capacity")
        capacity = _u64(capacity_raw)
        if capacity < 0x10:
            name_pointer = name_object
            name_pointer_hex = name_pointer.to_bytes(8, "little").hex()
            pointer_mode = "inline_object_base"
        else:
            name_pointer, name_pointer_hex = extension.pointer(name_object, f"{prefix}.name_heap_pointer")
            pointer_mode = "heap_pointer_at_object_base"
        name_probe = extension.read(name_pointer, MAX_NAME_BYTES, f"{prefix}.name_bytes")
        nul = name_probe.find(b"\0")
        if nul < 0:
            raise ValueError("dynamic_name_nul_not_found_within_1024")
        next_raw = extension.read(pointer + 0x10, 8, f"{prefix}.next")
        pending.append({
            "link_pointer_raw_hex": pointer.to_bytes(8, "little").hex(),
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
            "next_pointer_raw_hex": next_raw.hex(),
        })
        pointer = _optional_pointer(next_raw, f"{prefix}.next")
    state["item_count"] += len(pending)
    result["items"] = pending
    return result


def _capture_node_extensions(
    extension: ExtensionReader,
    base: int,
    node_id: str,
    entry_address: int,
    seed_node: dict[str, Any],
    table: int,
    state: dict[str, Any],
) -> dict[str, Any]:
    seed_entry = bytes.fromhex(seed_node["entry_raw_hex"])
    if len(seed_entry) != ENTRY_SIZE:
        raise ValueError("seed_entry_width_invalid")
    dynamic = _capture_dynamic_chain(
        extension, entry_address, node_id, state,
        seed_entry[DYNAMIC_OFFSET:DYNAMIC_OFFSET + 8].hex(),
    )
    completed: list[dict[str, Any]] = []
    before = state["item_count"]
    try:
        for offset, direction, native_key in (
            (TAIL_TO_OFFSET, "to", "TRANSFER_TRADE_POWER_TO"),
            (TAIL_FROM_OFFSET, "from", "TRANSFER_TRADE_POWER_FROM"),
        ):
            completed.append(_capture_tail_chain(
                extension, entry_address, offset, direction, native_key, table, state,
                seed_entry[offset:offset + 8].hex(), node_id,
            ))
    except Exception as exc:
        state["item_count"] = before
        return {
            "dynamic_sources": dynamic,
            "transfer_sources": {
                "to": {"status": "unknown", "reason": f"{type(exc).__name__}:{exc}", "items": [], "items_retracted": True},
                "from": {"status": "unknown", "reason": "node_tail_retracted_after_sibling_failure", "items": [], "items_retracted": True},
            },
            "items_retracted": True,
        }
    return {
        "dynamic_sources": dynamic,
        "transfer_sources": {"to": completed[0], "from": completed[1]},
        "items_retracted": False,
    }


def read_source_details_v3(reader: Any, base: int, country_pointer: int) -> dict[str, Any]:
    if not isinstance(country_pointer, int) or isinstance(country_pointer, bool):
        raise ValueError("country_pointer_must_be_integer")
    seed_document, seed_by_key = _load_seed()
    graph = read_trade(reader, base, country_pointer)
    if graph.get("country_reference_raw_hex") != seed_document["trade_source_details_inputs"][0]["country_fullref_raw_hex"]:
        raise ValueError("seed_country_fullref_mismatch")
    slot = graph.get("country_slot")
    if not isinstance(slot, int) or not 0 <= slot <= MAX_COUNTRY_SLOT:
        raise ValueError("country_slot_missing_or_unbounded")
    nodes = graph.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 81:
        raise ValueError("trade_graph_definition_count_mismatch")
    true_nodes = [node for node in nodes if int(node["predicate_rva"], 0) == TRUE_PREDICATE_RVA]
    false_nodes = [node for node in nodes if int(node["predicate_rva"], 0) == FALSE_PREDICATE_RVA]
    if len(true_nodes) != EXPECTED_TRUE_NODES or any(node.get("node_id") != "Null" for node in false_nodes):
        raise ValueError("trade_graph_predicate_count_mismatch")

    extension = ExtensionReader(reader)
    country_table_context = _read_country_table(
        extension, base, slot, graph["country_reference_raw_hex"],
    )
    table = int.from_bytes(bytes.fromhex(country_table_context["country_table_raw_hex"]), "little")
    state = {"item_count": 0}
    output_nodes = []
    seed_graph_nodes = {node["node_id"]: node for node in seed_document["trade_source_details_inputs"][0]["nodes"]}
    for node in true_nodes:
        node_id = node.get("node_id")
        if node_id not in seed_by_key or node_id not in seed_graph_nodes:
            raise ValueError(f"seed_node_missing:{node_id}")
        seed_node = seed_by_key[node_id]
        if node.get("entry_address") != seed_node.get("entry_address") or node.get("runtime_pointer") != seed_node.get("runtime_pointer"):
            raise ValueError(f"seed_node_pointer_mismatch:{node_id}")
        entry_address = _pointer(int(node["entry_address"], 0), f"entry.{node_id}")
        extensions = _capture_node_extensions(extension, base, node_id, entry_address, seed_node, table, state)
        copied = copy.deepcopy(seed_node)
        copied["runtime_pointer"] = node["runtime_pointer"]
        copied["entry_address"] = node["entry_address"]
        copied["dynamic_sources"] = extensions["dynamic_sources"]
        copied["transfer_sources"] = extensions["transfer_sources"]
        copied["tail_items_retracted"] = extensions["items_retracted"]
        copied["entry_chain_head_raw_hex"] = {
            "dynamic_0x90": seed_node["entry_raw_hex"][DYNAMIC_OFFSET * 2:(DYNAMIC_OFFSET + 8) * 2],
            "to_0x60": seed_node["entry_raw_hex"][TAIL_TO_OFFSET * 2:(TAIL_TO_OFFSET + 8) * 2],
            "from_0x78": seed_node["entry_raw_hex"][TAIL_FROM_OFFSET * 2:(TAIL_FROM_OFFSET + 8) * 2],
        }
        output_nodes.append(copied)

    return {
        "module_base": hex(base),
        "country": "FRA",
        "country_pointer_raw_hex": country_pointer.to_bytes(8, "little").hex(),
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
        "entry_read_bytes": 0,
        "v2_seed": {
            "path": SEED_PATH.relative_to(ROOT).as_posix(),
            "sha256": EXPECTED_SEED_SHA256,
            "fields_reused": ["entry_raw_hex", "share_raw", "source_inputs", "capital_condition"],
            "full_entries_reread": False,
        },
        "country_table_context": country_table_context,
        "extension_budget": {
            "max_bytes": MAX_EXTENSION_BYTES,
            "bytes_requested": extension.bytes_requested,
            "rpm_calls": extension.calls,
            "tail_items_completed": state["item_count"],
            "budget_exhausted": False,
            "max_country_slot_for_read": MAX_COUNTRY_SLOT,
            "max_items_per_node_across_three_chains": MAX_ITEMS_PER_NODE,
            "max_items_global_across_three_chains": MAX_ITEMS_GLOBAL,
        },
        "raw_input_semantics": "Frozen v2 entry/source/capital seed plus fresh bounded raw entry+0x60/+0x78 transfer chains, rechecked entry+0x90 head, and country-table object+0x20 fullref bindings; no public aggregation, sign rewrite, locale translation, or native call.",
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
        if not isinstance(date, dict) or date.get("value") != EXPECTED_DATE:
            failures.append(f"date_pass_{index}")
        nodes = record.get("trade_source_nodes") if isinstance(record, dict) else None
        if not isinstance(nodes, list) or len(nodes) != EXPECTED_TRUE_NODES:
            failures.append(f"true_nodes_pass_{index}")
        elif any("transfer_sources" not in node for node in nodes):
            failures.append(f"tail_shape_pass_{index}")
        budget = record.get("extension_budget", {}) if isinstance(record, dict) else {}
        if budget.get("bytes_requested", MAX_EXTENSION_BYTES + 1) > MAX_EXTENSION_BYTES:
            failures.append(f"extension_budget_pass_{index}")
    if failures:
        report["status"] = "identity_or_contract_mismatch"
        report["completed"] = False
        report.setdefault("errors", []).append({"stage": "strict_trade_source_details_v3_postcheck", "error": ";".join(failures)})
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
    static_pin = _static_pin()
    report = probe(args.installation, field="trade_source_details", input_reader=read_source_details_v3)
    report["probe"] = "information-independent-trade-source-details-v3-tail-runtime"
    report["probe_script"] = str(Path(__file__).resolve())
    report["probe_script_sha256"] = digest(Path(__file__).resolve())
    report["schema"] = "information_independent_trade_source_details_inputs.v3"
    report["field"] = "trade_source_details"
    report["request"]["fields"] = ["trade_source_details"]
    report["request"]["country_locator_fields"] = ["stability"]
    report["locator_dependency"] = {
        "underlying_probe_field": "stability",
        "purpose": "country/fullref/node locator only",
        "not_a_trade_source_guard": True,
    }
    report["trade_source_details_static_contract_guard"] = static_pin
    report["v2_seed"] = {
        "path": SEED_PATH.relative_to(ROOT).as_posix(),
        "sha256": EXPECTED_SEED_SHA256,
        "role": "frozen complete v2 entry/source/capital/dynamic raw seed; no full-entry reread",
    }
    report["capture_contract"] = {
        "reader": "read_trade locator plus fresh bounded entry+0x60/+0x78 chains and country_table[slot]+0x20 fullref checks; entry+0x90 head rechecked",
        "passes": 2,
        "true_predicate_rva": hex(TRUE_PREDICATE_RVA),
        "false_predicate_rva": hex(FALSE_PREDICATE_RVA),
        "expected_true_nodes_per_pass": EXPECTED_TRUE_NODES,
        "full_entries_reread": False,
        "max_single_rpm_bytes": MAX_SINGLE_RPM,
        "max_total_rpm_bytes": MAX_TOTAL_RPM,
        "max_extension_read_bytes_per_pass": MAX_EXTENSION_BYTES,
        "max_country_slot_for_read": MAX_COUNTRY_SLOT,
        "max_items_per_node_across_three_chains": MAX_ITEMS_PER_NODE,
        "max_items_global_across_three_chains": MAX_ITEMS_GLOBAL,
        "raw_only": True,
        "native_function_invoked": False,
        "target_memory_writes": False,
        "direction_from_container": True,
        "raw_sign_preserved": True,
        "country_tag_saved_only_after_exact_fullref_match": True,
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
        "extension_tail_items_per_pass": [
            item.get("extension_budget", {}).get("tail_items_completed")
            for item in report.get("trade_source_details_inputs", [])
        ],
        "full_entries_reread": False,
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
        "tail_items_per_pass": report.get("access_summary", {}).get("extension_tail_items_per_pass"),
        "handle_closed": report.get("access_summary", {}).get("handle_close", {}).get("closed"),
        "errors": report.get("errors"),
    }, ensure_ascii=False))
    return 0 if report.get("completed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
