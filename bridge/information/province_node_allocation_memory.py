"""Passive binding and allocation reader for a loaded trade-node province set.

The caller owns country admission/rebinding, province discovery admission and
the outer capture protocol.  This leaf only reads the currently loaded node
graph and its province contributions; it does not invoke native game code.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from typing import Any

from . import country_scale_development_memory as _country
from . import foreign_quality_memory as _quality
from . import province_reference_memory as _province_reference
from . import province_state_memory as _province_state
from . import trade_value_memory as _trade_value


FIELD = "G02.province_node_allocation"
BASIS = "native_trade_node_province_component_reconstruction"
PERIOD = "current"
SCALE = 1000
UNIT = "trade_power"

RECORD_STRIDE = 0x2E10
RECORD_ID_OFFSET = 0x20
PROVINCE_RUNTIME_OFFSET = 0xE8
RUNTIME_TABLE_OFFSET = 0x18
RUNTIME_COUNTRY_ENTRY_COUNT_OFFSET = 0x24
RUNTIME_DEFINITION_OFFSET = 0xA8
DEFINITION_PROVINCE_VECTOR_BEGIN_OFFSET = 0x68
DEFINITION_PROVINCE_VECTOR_END_OFFSET = 0x70
PROVINCE_DISCOVERY_OFFSET = 0x5E0
PROVINCE_CONTROLLER_FULLREF_OFFSET = 0x470
PROVINCE_OWNER_HIGH_BYTE_OFFSET = 0x46F
PROVINCE_TRADE_POWER_OFFSET = 0x890
NODE_ENTRY_STRIDE = 0xC0
NODE_ENTRY_PROVINCE_POWER_OFFSET = 0x28
MAX_NODE_PROVINCES = 512
MAX_NODE_PROVINCE_VECTOR_BYTES = MAX_NODE_PROVINCES * 8
MAX_PROVINCE_COUNT = 65536
MAX_COUNTRY_SLOTS = 4096

_SAFE_REASONS = {
    "input_invalid",
    "profile_unavailable",
    "binding_invalid",
    "province_scan_invalid",
    "candidate_runtime_invalid",
    "candidate_definition_invalid",
    "node_key_invalid",
    "node_identity_unknown",
    "node_identity_mismatch",
    "province_base_mismatch",
    "center_identity_invalid",
    "membership_vector_invalid",
    "membership_pointer_invalid",
    "membership_id_invalid",
    "member_runtime_mismatch",
    "selected_member_missing",
    "selected_province_not_observed",
    "selected_controller_mismatch",
    "selected_controller_invalid",
    "member_read_unknown",
    "cache_header_invalid",
    "cache_read_unknown",
    "snapshot_drift",
    "read_budget_exceeded",
    "read_failed",
}


class _LeafFailure(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason if reason in _SAFE_REASONS else "read_failed"


class _PassReader:
    def __init__(self, trace: Any, pass_number: int):
        self.trace = trace
        self.pass_number = pass_number

    def read(self, address: int, size: int, label: str) -> bytes:
        return self.trace.read(address, size, f"node_allocation.pass{self.pass_number}.{label}")


def _unknown(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    safe = reason if reason in _SAFE_REASONS else "read_failed"
    return {
        "status": "unknown",
        "reason": safe,
        "complete": False,
        "partial": True,
        "basis": BASIS,
        "period": PERIOD,
        "raw_inputs": deepcopy(dict(raw_inputs)) if isinstance(raw_inputs, Mapping) else {},
    }


def _address(value: Any, *, alignment: int = 1) -> bool:
    return _trade_value._valid_address(value, alignment=alignment)


def _parse_pointer(value: Any, label: str, *, alignment: int = 8) -> int:
    if type(value) is int:
        pointer = value
    elif type(value) is str:
        try:
            pointer = int(value, 0)
        except ValueError as exc:
            raise _LeafFailure("input_invalid") from exc
    else:
        raise _LeafFailure("input_invalid")
    if not _address(pointer, alignment=alignment):
        raise _LeafFailure("input_invalid")
    return pointer


def _checked_add(base: int, offset: int, label: str) -> int:
    try:
        return _trade_value._address_add(base, offset, label)
    except Exception as exc:
        raise _LeafFailure("input_invalid") from exc


def _read_exact(reader: Any, address: int, size: int, label: str) -> bytes:
    if (not _address(address) or type(size) is not int or size <= 0
            or size > _quality.MAX_SINGLE_READ_BYTES
            or address + size > _trade_value.MAX_USER_ADDRESS_EXCLUSIVE):
        raise _LeafFailure("input_invalid")
    try:
        raw = reader.read(address, size, label)
    except Exception as exc:
        trace = getattr(reader, "trace", reader)
        if getattr(trace, "budget_failed", False):
            raise _LeafFailure("read_budget_exceeded") from exc
        raise _LeafFailure("read_failed") from exc
    if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
        raise _LeafFailure("read_failed")
    return bytes(raw)


def _u64(reader: Any, address: int, label: str) -> tuple[int, bytes]:
    if not _address(address, alignment=8):
        raise _LeafFailure("input_invalid")
    raw = _read_exact(reader, address, 8, label)
    return int.from_bytes(raw, "little", signed=False), raw


def _i32(reader: Any, address: int, label: str) -> tuple[int, bytes]:
    if not _address(address, alignment=4):
        raise _LeafFailure("input_invalid")
    raw = _read_exact(reader, address, 4, label)
    return int.from_bytes(raw, "little", signed=True), raw


def _parse_country_binding(base: int, binding: Any) -> dict[str, Any]:
    if not isinstance(binding, Mapping):
        raise _LeafFailure("binding_invalid")
    try:
        parsed_base, _pointer, retained = _country._parse_target(base, binding)
        fullref = int(str(retained["fullref"]), 0)
        slot = retained["slot"]
        tag = retained["tag"]
        raw_hex = retained["fullref_raw_hex"]
    except Exception as exc:
        raise _LeafFailure("binding_invalid") from exc
    if (parsed_base != base or type(slot) is not int or not 0 <= slot < MAX_COUNTRY_SLOTS
            or type(tag) is not str or type(fullref) is not int
            or not 0 <= fullref <= 0xFFFFFFFFFFFFFFFF
            or binding.get("fullref_raw_hex") != raw_hex
            or binding.get("fullref") not in (hex(fullref), f"0x{fullref:016x}")
            or binding.get("slot") != slot or binding.get("tag") != tag
            or ((fullref >> 56) & 0xFF) == 0 or ((fullref >> 48) & 0xFF) == 7
            or ((fullref >> 32) & 0xFFFF) != slot
            or (fullref & 0xFFFFFFFF).to_bytes(4, "little")[:3].decode("ascii", errors="ignore") != tag
            or (fullref & 0xFF000000) != 0):
        raise _LeafFailure("binding_invalid")
    return {"tag": tag, "slot": slot, "fullref": hex(fullref),
            "fullref_raw_hex": raw_hex, "country_pointer": retained["country_pointer"]}


def _parse_province_binding(scan: Any, binding: Any) -> dict[str, Any]:
    if not isinstance(scan, Mapping) or scan.get("status") != "observed" or not isinstance(binding, Mapping):
        raise _LeafFailure("province_scan_invalid")
    header = scan.get("header")
    if not isinstance(header, Mapping):
        raise _LeafFailure("province_scan_invalid")
    try:
        records = _parse_pointer(header.get("records_pointer"), "records_pointer")
        count = header.get("count")
    except _LeafFailure as exc:
        raise _LeafFailure("province_scan_invalid") from exc
    if type(count) is not int or not 1 < count <= MAX_PROVINCE_COUNT:
        raise _LeafFailure("province_scan_invalid")
    records_end = records + count * RECORD_STRIDE
    if records_end <= records or records_end > _trade_value.MAX_USER_ADDRESS_EXCLUSIVE:
        raise _LeafFailure("province_scan_invalid")
    declared_range = header.get("records_range")
    if declared_range is not None:
        if (not isinstance(declared_range, (list, tuple)) or len(declared_range) != 2
                or _parse_pointer(declared_range[0], "records_range_start") != records
                or _parse_pointer(declared_range[1], "records_range_end", alignment=1) != records_end):
            raise _LeafFailure("province_scan_invalid")

    province_id = binding.get("province_id")
    record_id = binding.get("record_id")
    id_address_raw = binding.get("id_address")
    record_raw = binding.get("record_pointer")
    id_raw_hex = binding.get("id_raw_hex")
    if (type(province_id) is not int or not 1 <= province_id < count
            or type(record_id) is not int or record_id != province_id
            or type(record_raw) is not str or type(id_address_raw) is not str
            or type(id_raw_hex) is not str or len(id_raw_hex) != 8):
        raise _LeafFailure("province_scan_invalid")
    try:
        record = int(record_raw, 0)
        id_address = int(id_address_raw, 0)
        id_raw = bytes.fromhex(id_raw_hex)
    except (ValueError, TypeError) as exc:
        raise _LeafFailure("province_scan_invalid") from exc
    expected_record = records + province_id * RECORD_STRIDE
    if (record != expected_record or not _address(record, alignment=8)
            or id_address != record + RECORD_ID_OFFSET or len(id_raw) != 4
            or int.from_bytes(id_raw, "little", signed=True) != province_id):
        raise _LeafFailure("province_scan_invalid")
    requested = scan.get("requested")
    if isinstance(requested, Mapping):
        scanned_binding = requested.get(str(province_id))
        if isinstance(scanned_binding, Mapping):
            if (scanned_binding.get("province_id") != province_id
                    or scanned_binding.get("record_id") != province_id
                    or scanned_binding.get("record_pointer") != record_raw
                    or scanned_binding.get("id_raw_hex") != id_raw_hex):
                raise _LeafFailure("province_scan_invalid")
    return {
        "province_id": province_id,
        "record_id": record_id,
        "record_pointer": record,
        "record_pointer_hex": hex(record),
        "id_address": id_address,
        "id_raw_hex": id_raw.hex(),
        "records_pointer": records,
        "records_pointer_hex": hex(records),
        "records_count": count,
        "records_end": records_end,
    }


def _decode_fullref(raw: bytes) -> dict[str, Any] | None:
    if len(raw) != 8:
        return None
    fullref = int.from_bytes(raw, "little", signed=False)
    high_byte = (fullref >> 56) & 0xFF
    byte48 = (fullref >> 48) & 0xFF
    slot = (fullref >> 32) & 0xFFFF
    low = (fullref & 0xFFFFFFFF).to_bytes(4, "little")
    if (fullref == 0 or high_byte == 0 or byte48 == 7 or slot >= MAX_COUNTRY_SLOTS
            or low[3] != 0 or not all(0x41 <= byte <= 0x5A for byte in low[:3])):
        return None
    return {"fullref": fullref, "fullref_hex": hex(fullref), "slot": slot,
            "tag": low[:3].decode("ascii"), "raw_hex": raw.hex(),
            "high_byte": high_byte, "byte48": byte48}


def _i32_wrap(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _identity_digest(node: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    raw_inputs = node.get("raw_inputs")
    identity = raw_inputs.get("identity") if isinstance(raw_inputs, Mapping) else None
    if not isinstance(identity, Mapping):
        raise _LeafFailure("node_identity_unknown")
    try:
        province_base = int(str(identity["province_base_pointer"]), 0)
        center = node.get("center_province_id")
        runtime = _parse_pointer(node.get("runtime_pointer"), "node_runtime")
        definition = _parse_pointer(node.get("definition_pointer"), "node_definition")
        manager = _parse_pointer(identity.get("manager_pointer"), "manager_pointer")
        begin = _parse_pointer(identity.get("definitions_begin"), "definitions_begin")
        end = _parse_pointer(identity.get("definitions_end"), "definitions_end")
        count = identity.get("definition_count")
        vector = identity.get("definition_vector_raw_hex")
    except Exception as exc:
        raise _LeafFailure("node_identity_unknown") from exc
    if (type(center) is not int or not 1 <= center <= 32767
            or type(count) is not int or not 1 <= count <= 1024
            or type(vector) is not str or len(vector) != count * 16):
        raise _LeafFailure("node_identity_unknown")
    try:
        digest_input = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except Exception as exc:
        raise _LeafFailure("node_identity_unknown") from exc
    digest = hashlib.sha256(digest_input).hexdigest()
    summary = {
        "manager_pointer": hex(manager),
        "definitions_begin": hex(begin),
        "definitions_end": hex(end),
        "definition_count": count,
        "definition_vector_sha256": hashlib.sha256(bytes.fromhex(vector)).hexdigest(),
        "province_base_pointer": hex(province_base),
        "center_province_id": center,
        "definition_pointer": hex(definition),
        "runtime_pointer": hex(runtime),
        "identity_sha256": digest,
    }
    return digest, summary


def _read_snapshot(reader: Any, trace: Any, pass_number: int, base: int,
                   province: Mapping[str, Any], observer: Mapping[str, Any],
                   controller: Mapping[str, Any], layout: Mapping[str, int]) -> dict[str, Any]:
    prefixed = _PassReader(trace, pass_number)
    selected_record = province["record_pointer"]
    selected_id = province["province_id"]
    records = province["records_pointer"]
    province_count = province["records_count"]

    selected_runtime_address = _checked_add(selected_record, PROVINCE_RUNTIME_OFFSET,
                                            "selected.runtime")
    runtime, runtime_raw = _u64(prefixed, selected_runtime_address,
                                "province.selected.runtime_pointer")
    if not _address(runtime, alignment=8):
        raise _LeafFailure("candidate_runtime_invalid")
    definition_address = _checked_add(runtime, RUNTIME_DEFINITION_OFFSET,
                                      "selected.runtime_definition")
    definition, definition_raw = _u64(prefixed, definition_address,
                                      "province.selected.runtime_definition")
    if not _address(definition, alignment=8):
        raise _LeafFailure("candidate_definition_invalid")

    ctx = _trade_value._Budget(prefixed, layout)
    try:
        definition_header = ctx.read(definition, 0x30, "node_allocation.candidate.definition_header")
        node_id, key_evidence = _trade_value._parse_node_key(
            ctx, definition, definition_header, layout, -1
        )
    except Exception as exc:
        if getattr(trace, "budget_failed", False):
            raise _LeafFailure("read_budget_exceeded") from exc
        raise _LeafFailure("node_key_invalid") from exc

    try:
        node = _trade_value.find_node(prefixed, base, node_id)
    except Exception as exc:
        if getattr(trace, "budget_failed", False):
            raise _LeafFailure("read_budget_exceeded") from exc
        raise _LeafFailure("node_identity_unknown") from exc
    if not isinstance(node, Mapping) or node.get("status") != "known":
        if getattr(trace, "budget_failed", False):
            raise _LeafFailure("read_budget_exceeded")
        raise _LeafFailure("node_identity_unknown")
    identity_digest, identity_summary = _identity_digest(node)
    try:
        node_definition = int(str(node["definition_pointer"]), 0)
        node_runtime = int(str(node["runtime_pointer"]), 0)
        center = node["center_province_id"]
        if node.get("node_id") != node_id:
            raise ValueError("node_id")
    except Exception as exc:
        raise _LeafFailure("node_identity_unknown") from exc
    if node_runtime != runtime or node_definition != definition:
        raise _LeafFailure("node_identity_mismatch")
    if identity_summary["province_base_pointer"] != hex(records):
        raise _LeafFailure("province_base_mismatch")
    if type(center) is not int or not 1 <= center < province_count:
        raise _LeafFailure("center_identity_invalid")

    center_record = records + center * RECORD_STRIDE
    center_id, center_id_raw = _i32(prefixed, center_record + RECORD_ID_OFFSET,
                                    "node_allocation.center.record_id")
    if center_id != center:
        raise _LeafFailure("center_identity_invalid")
    center_runtime, center_runtime_raw = _u64(
        prefixed, center_record + PROVINCE_RUNTIME_OFFSET,
        "node_allocation.center.runtime_pointer",
    )
    if center_runtime != runtime:
        raise _LeafFailure("node_identity_mismatch")

    vector_header_raw = _read_exact(
        prefixed, definition + DEFINITION_PROVINCE_VECTOR_BEGIN_OFFSET,
        16, "node_allocation.definition.province_vector_header",
    )
    vector_begin = int.from_bytes(vector_header_raw[:8], "little", signed=False)
    vector_end = int.from_bytes(vector_header_raw[8:], "little", signed=False)
    if (not _address(vector_begin, alignment=8) or not _address(vector_end, alignment=8)
            or vector_end <= vector_begin or vector_end - vector_begin > MAX_NODE_PROVINCE_VECTOR_BYTES
            or (vector_end - vector_begin) % 8):
        raise _LeafFailure("membership_vector_invalid")
    member_count = (vector_end - vector_begin) // 8
    if not 1 <= member_count <= MAX_NODE_PROVINCES:
        raise _LeafFailure("membership_vector_invalid")
    vector_raw = _read_exact(prefixed, vector_begin, member_count * 8,
                             "node_allocation.definition.province_vector")
    member_pointers = [int.from_bytes(vector_raw[i:i + 8], "little", signed=False)
                       for i in range(0, len(vector_raw), 8)]
    if len(set(member_pointers)) != member_count:
        raise _LeafFailure("membership_vector_invalid")

    if selected_record not in member_pointers:
        raise _LeafFailure("selected_member_missing")

    observer_slot = observer["slot"]
    observed_count = 0
    observed_sum = 0
    sum_complete = True
    selected_data: dict[str, Any] | None = None
    member_evidence: list[dict[str, Any]] = []

    for member_index, member_record in enumerate(member_pointers):
        if not _address(member_record, alignment=8):
            raise _LeafFailure("membership_pointer_invalid")
        if not records <= member_record < province["records_end"]:
            raise _LeafFailure("membership_pointer_invalid")
        if (member_record - records) % RECORD_STRIDE:
            raise _LeafFailure("membership_pointer_invalid")
        member_id, member_id_raw = _i32(
            prefixed, member_record + RECORD_ID_OFFSET,
            f"node_allocation.member[{member_index}].record_id",
        )
        if (not 1 <= member_id < province_count
                or records + member_id * RECORD_STRIDE != member_record):
            raise _LeafFailure("membership_id_invalid")
        member_runtime, member_runtime_raw = _u64(
            prefixed, member_record + PROVINCE_RUNTIME_OFFSET,
            f"node_allocation.member[{member_index}].runtime_pointer",
        )
        if member_runtime != runtime:
            raise _LeafFailure("member_runtime_mismatch")

        is_selected = member_record == selected_record
        discovery = _province_state._read_discovery(prefixed, member_record, observer_slot)
        row: dict[str, Any] = {
            "index": member_index,
            "record_pointer": hex(member_record),
            "province_id": member_id,
            "id_raw_hex": member_id_raw.hex(),
            "runtime_raw_hex": member_runtime_raw.hex(),
            "discovery": deepcopy(dict(discovery)) if isinstance(discovery, Mapping) else None,
            "selected": is_selected,
        }
        if not isinstance(discovery, Mapping) or discovery.get("status") != "known" or discovery.get("value") is not True:
            sum_complete = False
            row["observer_contribution_status"] = "not_observed"
            member_evidence.append(row)
            if is_selected:
                selected_data = None
            continue

        try:
            controller_raw = _read_exact(
                prefixed, member_record + PROVINCE_CONTROLLER_FULLREF_OFFSET, 8,
                f"node_allocation.member[{member_index}].controller_fullref",
            )
        except _LeafFailure:
            if is_selected:
                raise _LeafFailure("selected_controller_invalid")
            if getattr(trace, "budget_failed", False):
                raise _LeafFailure("read_budget_exceeded")
            sum_complete = False
            row["observer_contribution_status"] = "controller_unknown"
            member_evidence.append(row)
            continue
        decoded_controller = _decode_fullref(controller_raw)
        if decoded_controller is None:
            if is_selected:
                raise _LeafFailure("selected_controller_invalid")
            row["controller_fullref_raw_hex"] = controller_raw.hex()
            try:
                invalid_controller_owner_raw = _read_exact(
                    prefixed, member_record + PROVINCE_OWNER_HIGH_BYTE_OFFSET, 1,
                    f"node_allocation.member[{member_index}].owner_high_byte_invalid_controller",
                )
            except _LeafFailure:
                if getattr(trace, "budget_failed", False):
                    raise _LeafFailure("read_budget_exceeded")
                sum_complete = False
                row["observer_contribution_status"] = "controller_invalid_owner_unknown"
                member_evidence.append(row)
                continue
            row["owner_high_byte_raw_hex"] = invalid_controller_owner_raw.hex()
            if invalid_controller_owner_raw[0] == 0:
                # The native writer adds no component for an ownerless
                # province, regardless of the malformed/stale controller ref.
                # Keep the owner byte as evidence and never read +0x890.
                observed_count += 1
                row["owner_present"] = False
                row["observer_contribution_raw"] = 0
                row["trade_power_raw"] = None
                row["observer_contribution_status"] = "known_owner_absent"
            else:
                sum_complete = False
                row["owner_present"] = True
                row["observer_contribution_status"] = "controller_invalid_owner_present"
            member_evidence.append(row)
            continue
        row["controller_fullref_raw_hex"] = controller_raw.hex()
        row["controller_tag"] = decoded_controller["tag"]
        row["controller_slot"] = decoded_controller["slot"]

        if is_selected:
            if (decoded_controller["fullref_hex"] != controller["fullref"]
                    or decoded_controller["tag"] != controller["tag"]
                    or decoded_controller["slot"] != controller["slot"]):
                raise _LeafFailure("selected_controller_mismatch")

        if decoded_controller["slot"] == observer_slot and decoded_controller["fullref_hex"] != observer["fullref"]:
            sum_complete = False
            row["observer_contribution_status"] = "same_slot_fullref_mismatch"
            if is_selected:
                raise _LeafFailure("selected_controller_mismatch")
            member_evidence.append(row)
            continue

        is_observer_recipient = decoded_controller["fullref_hex"] == observer["fullref"]
        needs_selected_contribution = is_selected
        needs_observer_contribution = is_observer_recipient
        owner_present: bool | None = None
        owner_raw: bytes | None = None
        contribution = 0
        trade_power_raw: bytes | None = None
        if needs_selected_contribution or needs_observer_contribution:
            try:
                owner_raw = _read_exact(
                    prefixed, member_record + PROVINCE_OWNER_HIGH_BYTE_OFFSET, 1,
                    f"node_allocation.member[{member_index}].owner_high_byte",
                )
                owner_present = owner_raw[0] != 0
                if owner_present:
                    contribution, trade_power_raw = _i32(
                        prefixed, member_record + PROVINCE_TRADE_POWER_OFFSET,
                        f"node_allocation.member[{member_index}].trade_power_i32",
                    )
                else:
                    contribution = 0
            except _LeafFailure:
                if is_selected:
                    raise _LeafFailure("member_read_unknown")
                if getattr(trace, "budget_failed", False):
                    raise _LeafFailure("read_budget_exceeded")
                sum_complete = False
                row["observer_contribution_status"] = "owner_or_power_unknown"
                member_evidence.append(row)
                continue

        if needs_observer_contribution:
            observed_sum = _i32_wrap(observed_sum + contribution)
            row["observer_contribution_raw"] = contribution
        else:
            row["observer_contribution_raw"] = 0
        observed_count += 1
        row["owner_high_byte_raw_hex"] = owner_raw.hex() if owner_raw is not None else None
        row["owner_present"] = owner_present
        row["trade_power_raw_hex"] = trade_power_raw.hex() if trade_power_raw is not None else None
        row["trade_power_raw"] = contribution if owner_present else 0 if owner_raw is not None else None
        row["observer_contribution_status"] = "known"
        member_evidence.append(row)

        if is_selected:
            selected_data = {
                "owner_present": bool(owner_present),
                "contribution_raw": contribution if owner_present else 0,
                "observer_contribution_raw": contribution if is_observer_recipient and owner_present else 0,
                "recipient_country": decoded_controller["tag"],
                "controller_fullref_raw_hex": controller_raw.hex(),
                "owner_high_byte_raw_hex": owner_raw.hex() if owner_raw is not None else None,
                "trade_power_raw_hex": trade_power_raw.hex() if trade_power_raw is not None else None,
            }

    if selected_data is None:
        raise _LeafFailure("selected_province_not_observed")

    entry_count, entry_count_raw = _i32(
        prefixed, runtime + RUNTIME_COUNTRY_ENTRY_COUNT_OFFSET,
        "node_allocation.runtime.country_entry_count",
    )
    if not 1 <= entry_count <= MAX_COUNTRY_SLOTS or observer_slot >= entry_count:
        raise _LeafFailure("cache_header_invalid")
    table_pointer, table_pointer_raw = _u64(
        prefixed, runtime + RUNTIME_TABLE_OFFSET,
        "node_allocation.runtime.country_entry_table",
    )
    if not _address(table_pointer, alignment=8) or table_pointer == runtime:
        raise _LeafFailure("cache_header_invalid")
    row_offset = observer_slot * NODE_ENTRY_STRIDE + NODE_ENTRY_PROVINCE_POWER_OFFSET
    cache_address = table_pointer + row_offset
    if (cache_address > _trade_value.MAX_USER_ADDRESS_EXCLUSIVE - 4
            or not _address(cache_address, alignment=4)):
        raise _LeafFailure("cache_header_invalid")
    try:
        cache_raw, cache_raw_bytes = _i32(prefixed, cache_address,
                                           "node_allocation.observer_cache_i32")
    except _LeafFailure as exc:
        if getattr(trace, "budget_failed", False):
            raise _LeafFailure("read_budget_exceeded") from exc
        raise _LeafFailure("cache_read_unknown") from exc

    matches = observed_sum == cache_raw if sum_complete else None
    identity_raw = node["raw_inputs"]["identity"]
    stable = {
        "province": {key: province[key] for key in (
            "province_id", "record_pointer_hex", "id_raw_hex", "records_pointer_hex", "records_count")},
        "candidate": {"runtime_raw_hex": runtime_raw.hex(),
                      "definition_raw_hex": definition_raw.hex(),
                      "definition_header_raw_hex": definition_header.hex(),
                      "key": deepcopy(key_evidence)},
        "node_identity_sha256": identity_digest,
        "node_identity": identity_summary,
        "center_id_raw_hex": center_id_raw.hex(),
        "center_runtime_raw_hex": center_runtime_raw.hex(),
        "definition_province_vector_header_raw_hex": vector_header_raw.hex(),
        "definition_province_vector_raw_hex": vector_raw.hex(),
        "members": member_evidence,
        "observer_binding": deepcopy(dict(observer)),
        "controller_binding": deepcopy(dict(controller)),
        "runtime_country_entry_count_raw_hex": entry_count_raw.hex(),
        "runtime_country_entry_count": entry_count,
        "runtime_table_pointer_raw_hex": table_pointer_raw.hex(),
        "observer_cache_address": hex(cache_address),
        "observer_cache_raw_hex": cache_raw_bytes.hex(),
        "observer_cache_raw": cache_raw,
        "observer_sum_raw": observed_sum,
        "observer_sum_complete": sum_complete,
        "observed_member_count": observed_count,
        "selected": deepcopy(selected_data),
    }
    value = {
        "node_id": node_id,
        "center_province_id": center,
        "province_id": selected_id,
        "recipient_country": selected_data["recipient_country"],
        "contribution_raw": selected_data["contribution_raw"],
        "observer_country": observer["tag"],
        "observer_contribution_raw": selected_data["observer_contribution_raw"],
        "observer_node_province_power_cache_raw": cache_raw,
        "observed_observer_province_power_sum_raw": observed_sum,
        "observer_sum_complete": sum_complete,
        "matches_observer_cache": matches,
        "member_count": member_count,
        "observed_member_count": observed_count,
        "owner_present": selected_data["owner_present"],
        "scale": SCALE,
        "unit": UNIT,
    }
    evidence = {
        "node_id": node_id,
        "candidate_runtime_pointer": hex(runtime),
        "candidate_definition_pointer": hex(definition),
        "candidate_key": deepcopy(key_evidence),
        "find_node_identity": identity_summary,
        "find_node_identity_sha256": identity_digest,
        "province_scan_header": {
            "records_pointer": province["records_pointer_hex"],
            "count": province_count,
            "records_end": hex(province["records_end"]),
        },
        "member_count": member_count,
        "members": member_evidence,
        "observer_cache_address": hex(cache_address),
        "observer_cache_raw_hex": cache_raw_bytes.hex(),
        "stable": stable,
    }
    return {"stable": stable, "value": value, "evidence": evidence}


def _snapshot_pair_digest(snapshot: Mapping[str, Any]) -> str:
    try:
        stable_raw = json.dumps(snapshot["stable"], sort_keys=True,
                                separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except Exception as exc:
        raise _LeafFailure("snapshot_drift") from exc
    return hashlib.sha256(stable_raw).hexdigest()


def read_fields(reader: Any, base: Any, province_binding: Any, province_scan: Any,
                observer_binding: Any, controller_binding: Any) -> dict[str, dict[str, Any]]:
    """Read the selected province contribution and observer’s node subtotal.

    Two complete snapshots are compared inside the leaf.  The caller still
    owns session validation, country admission/rebinding, discovery admission,
    and its own capture-level two-pass comparison.
    """
    trace = _quality._TraceReader(reader)
    try:
        if type(base) is not int or not _address(base, alignment=8):
            raise _LeafFailure("input_invalid")
        observer = _parse_country_binding(base, observer_binding)
        controller = _parse_country_binding(base, controller_binding)
        if (controller["slot"] == observer["slot"]
                and controller["fullref"] != observer["fullref"]):
            raise _LeafFailure("binding_invalid")
        province = _parse_province_binding(province_scan, province_binding)
        try:
            profile = _trade_value.load_profile()
            layout = _trade_value._validate_layout(profile)
        except Exception as exc:
            raise _LeafFailure("profile_unavailable") from exc

        first = _read_snapshot(reader, trace, 1, base, province, observer,
                               controller, layout)
        second = _read_snapshot(reader, trace, 2, base, province, observer,
                                controller, layout)
        first_digest = _snapshot_pair_digest(first)
        second_digest = _snapshot_pair_digest(second)
        if first_digest != second_digest or first["stable"] != second["stable"]:
            raise _LeafFailure("snapshot_drift")

        raw_inputs = {
            "trade_value_profile_sha256": _trade_value.PROFILE_SHA256,
            "province_binding": {
                "province_id": province["province_id"],
                "record_id": province["record_id"],
                "record_pointer": province["record_pointer_hex"],
                "id_address": hex(province["id_address"]),
                "id_raw_hex": province["id_raw_hex"],
            },
            "observer_binding": deepcopy(observer),
            "controller_binding": deepcopy(controller),
            "pass_summaries": [first["evidence"], second["evidence"]],
            "snapshot_sha256": [first_digest, second_digest],
            "reads": deepcopy(trace.reads),
            "read_budget": trace.budget(),
        }
        component = {
            "status": "known",
            "value": first["value"],
            "complete": False,
            "partial": True,
            "basis": BASIS,
            "period": PERIOD,
            "raw_inputs": raw_inputs,
        }
        return {FIELD: component}
    except _LeafFailure as exc:
        reason = exc.reason
    except Exception:
        reason = "read_failed"
    raw_inputs = {
        "trade_value_profile_sha256": _trade_value.PROFILE_SHA256,
        "reads": deepcopy(trace.reads),
        "read_budget": trace.budget(),
    }
    return {FIELD: _unknown(reason, raw_inputs)}


__all__ = ["BASIS", "FIELD", "PERIOD", "SCALE", "UNIT", "read_fields"]
