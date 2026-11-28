"""Bounded membership/role evidence for the native country node-power sum.

This leaf consumes an already validated trade-income record and the
country-resources 256-entry identity scan.  It does not scan the country table,
call native functions, or read any country's power value.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import country_reference_memory as _country_refs
from . import trade_income_memory as _trade


BASIS = "native_global_country_power_sum_membership"
PERIOD = "current"
DATABASE_GLOBAL_RVA = 0x233D8B0
DATABASE_TABLE_OFFSET = 0x118
WORLD_GLOBAL_RVA = 0x233FE58
WORLD_MEMBER_LIST_OFFSET = 0x1D08
WORLD_MEMBER_COUNT_OFFSET = 0x1D14
WORLD_HUMAN_COUNT_OFFSET = 0xA60
WORLD_CONTROLLERS_OFFSET = 0x1D48
COUNTRY_FULLREF_OFFSET = 0x20
CONTROLLER_I32_STRIDE = 4
MAX_COUNTRY_SLOTS = 4096
MAX_SOURCE_SCAN_ENTRIES = 256
MAX_SINGLE_READ = 32 * 1024
MAX_TOTAL_READ = 128 * 1024
MAX_READ_CALLS = 8192


class _Unknown(Exception):
    def __init__(self, reason: str):
        self.reason = reason


def _is_int(value: Any) -> bool:
    return type(value) is int


def _valid_pointer(value: Any) -> bool:
    return _is_int(value) and _trade._valid_address(value) and value & 7 == 0


def _parse_pointer(value: Any) -> int | None:
    if isinstance(value, Mapping):
        value = value.get("va")
    if _is_int(value):
        return value if _valid_pointer(value) else None
    result = _trade._pointer_from_hex(value)
    return result if result is not None and result & 7 == 0 else None


def _add(address: int, offset: int, size: int = 1) -> int:
    if not _valid_pointer(address) or not _is_int(offset) or offset < 0:
        raise _Unknown("address_invalid")
    if not _is_int(size) or size <= 0:
        raise _Unknown("address_invalid")
    result = address + offset
    if not _trade._valid_address(result) or result + size - 1 > _trade.MAX_USER_ADDRESS:
        raise _Unknown("address_invalid")
    return result


def _parse_u64_hex(value: Any) -> tuple[int, bytes] | None:
    if not isinstance(value, str) or len(value) != 16:
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    if len(raw) != 8:
        return None
    return int.from_bytes(raw, "little", signed=False), raw


def _parse_u64_text(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = int(value, 0)
    except ValueError:
        return None
    return parsed if 0 <= parsed <= 0xFFFFFFFFFFFFFFFF else None


def _read_qword(trace: "_Trace", address: int, label: str) -> tuple[int, bytes]:
    raw = trace.read(address, 8, label)
    return int.from_bytes(raw, "little", signed=False), raw


def _read_i32(trace: "_Trace", address: int, label: str) -> tuple[int, bytes]:
    raw = trace.read(address, 4, label)
    return int.from_bytes(raw, "little", signed=True), raw


class _Trace:
    def __init__(self, reader: Any):
        self.reader = reader
        self.bytes_requested = 0
        self.calls = 0
        self.reads: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        if not _is_int(address) or not _trade._valid_address(address):
            raise _Unknown("address_invalid")
        if (not _is_int(size) or size <= 0 or size > MAX_SINGLE_READ
                or not isinstance(label, str) or not label.startswith("trade_power_sum.")):
            raise _Unknown("read_request_invalid")
        if self.calls >= MAX_READ_CALLS or self.bytes_requested + size > MAX_TOTAL_READ:
            raise _Unknown("read_budget_exceeded")
        if address + size - 1 > _trade.MAX_USER_ADDRESS:
            raise _Unknown("address_invalid")
        self.calls += 1
        self.bytes_requested += size
        attempt: dict[str, Any] = {
            "address": hex(address), "size": size, "label": label,
            "raw_hex": None, "bytes_received": None,
        }
        self.reads.append(attempt)
        method = getattr(self.reader, "read", None)
        if not callable(method):
            raise _Unknown("reader_invalid")
        try:
            raw = method(address, size, label)
        except Exception:
            raise _Unknown("read_failed") from None
        if not isinstance(raw, (bytes, bytearray)):
            raise _Unknown("read_failed")
        attempt["bytes_received"] = len(raw)
        attempt["raw_hex"] = bytes(raw).hex()
        if len(raw) != size:
            raise _Unknown("short_read")
        return bytes(raw)


def _source_identity(trade_record: Any, country_scan: Any) -> dict[str, Any]:
    if not isinstance(trade_record, Mapping) or not _trade.validate_record(trade_record):
        raise _Unknown("trade_income_record_invalid")
    country = trade_record.get("country")
    trade_pointer = _parse_pointer(trade_record.get("country_pointer"))
    trade_ref = _parse_u64_hex(trade_record.get("country_fullref_raw_hex"))
    trade_slot = trade_record.get("country_slot")
    if trade_pointer is None or trade_ref is None or not _is_int(trade_slot):
        raise _Unknown("trade_income_identity_invalid")
    if (_country_refs._tag_from_fullref(trade_ref[0]) != country
            or int.from_bytes(trade_ref[1][4:6], "little", signed=True) != trade_slot):
        raise _Unknown("trade_income_identity_invalid")
    if trade_record.get("country_fullref_address") != hex(
        _add(trade_pointer, COUNTRY_FULLREF_OFFSET, 8)
    ):
        raise _Unknown("trade_income_fullref_address_invalid")

    if not isinstance(country_scan, Mapping) or country_scan.get("status") != "observed":
        raise _Unknown("country_scan_not_observed")
    if country_scan.get("requested_country") != country:
        raise _Unknown("country_scan_country_mismatch")
    if country_scan.get("scanned_entries") != MAX_SOURCE_SCAN_ENTRIES:
        raise _Unknown("country_scan_window_invalid")
    matches = country_scan.get("matches")
    if not isinstance(matches, list) or len(matches) != 1 or not isinstance(matches[0], Mapping):
        raise _Unknown("country_scan_match_not_unique")
    match = matches[0]

    scan_pointer = _parse_pointer(country_scan.get("country_pointer"))
    match_pointer = _parse_pointer(match.get("country_pointer"))
    table_field = country_scan.get("table_field")
    if not isinstance(table_field, Mapping) or not isinstance(table_field.get("address"), Mapping):
        raise _Unknown("country_scan_table_field_invalid")
    table_cell = _parse_pointer(table_field["address"].get("va"))
    table_value = _parse_pointer(table_field.get("value"))
    table_raw_pair = _parse_u64_hex(table_field.get("raw_hex"))
    if (table_cell is None or table_value is None or table_raw_pair is None
            or table_raw_pair[0] != table_value):
        raise _Unknown("country_scan_table_field_invalid")

    handle = country_scan.get("country_handle")
    if not isinstance(handle, Mapping):
        handle = match.get("country_handle")
    if not isinstance(handle, Mapping):
        raise _Unknown("country_scan_handle_invalid")
    handle_raw_pair = _parse_u64_hex(handle.get("raw_hex"))
    handle_value = handle.get("value")
    handle_value_parsed = _parse_u64_text(handle_value)
    handle_address = _parse_pointer(handle.get("address"))
    handle_tag = handle.get("tag")
    handle_slot = handle.get("slot")
    table_index = match.get("table_index")
    if (handle_raw_pair is None or handle_value_parsed is None
            or handle_value_parsed != handle_raw_pair[0]
            or handle_tag != country or not _is_int(handle_slot)
            or not _is_int(table_index)):
        raise _Unknown("country_scan_handle_invalid")
    raw_tag = _country_refs._tag_from_fullref(handle_raw_pair[0])
    raw_slot = int.from_bytes(handle_raw_pair[1][4:6], "little", signed=True)
    if raw_tag != country or raw_slot != handle_slot:
        raise _Unknown("country_scan_handle_invalid")

    if (scan_pointer is None or match_pointer is None or scan_pointer != match_pointer
            or scan_pointer != trade_pointer or match.get("table_index") != handle_slot
            or handle_slot != trade_slot or handle_raw_pair[1] != trade_ref[1]
            or handle_address != trade_pointer + COUNTRY_FULLREF_OFFSET):
        raise _Unknown("canonical_binding_mismatch")
    if not 0 <= trade_slot < MAX_SOURCE_SCAN_ENTRIES:
        raise _Unknown("canonical_slot_out_of_range")
    if not 0 <= trade_slot < MAX_COUNTRY_SLOTS:
        raise _Unknown("canonical_slot_out_of_range")

    return {
        "country_pointer": trade_pointer,
        "country_fullref_raw": trade_ref[1],
        "country_fullref": trade_ref[0],
        "country_slot": trade_slot,
        "source_table_cell": table_cell,
        "source_table_pointer": table_value,
        "source_table_raw_hex": table_raw_pair[1].hex(),
        "source_country_handle_raw_hex": handle_raw_pair[1].hex(),
        "source_table_index": table_index,
    }


def _unknown(reason: str, trace: _Trace, *, private: Mapping[str, Any] | None = None,
             membership: Mapping[str, Any] | None = None,
             country_slot: int | None = None) -> dict[str, Any]:
    raw_inputs: dict[str, Any] = {
        "reads": trace.reads,
        "budget": {"calls": trace.calls, "bytes_requested": trace.bytes_requested,
                   "max_calls": MAX_READ_CALLS, "max_bytes": MAX_TOTAL_READ,
                   "max_single_read": MAX_SINGLE_READ},
    }
    if private:
        raw_inputs.update(private)
    result: dict[str, Any] = {
        "status": "unknown", "reason": reason, "basis": BASIS,
        "period": PERIOD, "complete": False, "raw_inputs": raw_inputs,
    }
    if membership is not None:
        result["membership"] = dict(membership)
    if country_slot is not None:
        result["country_slot"] = country_slot
    return result


def read_fields(reader: Any, module_base: int, trade_income_record: Any,
                country_scan: Any) -> dict[str, Any]:
    """Verify the selected country’s unique membership and NPC role."""
    trace = _Trace(reader)
    private: dict[str, Any] = {}
    membership: dict[str, Any] = {}
    country_slot: int | None = None
    try:
        identity = _source_identity(trade_income_record, country_scan)
        country_slot = identity["country_slot"]
        private.update({
            "module_base": hex(module_base) if _valid_pointer(module_base) else None,
            "country_pointer": hex(identity["country_pointer"]),
            "country_fullref_raw_hex": identity["country_fullref_raw"].hex(),
            "source_table_cell": hex(identity["source_table_cell"]),
            "source_table_pointer": hex(identity["source_table_pointer"]),
            "source_table_raw_hex": identity["source_table_raw_hex"],
            "source_country_handle_raw_hex": identity["source_country_handle_raw_hex"],
            "source_table_index": identity["source_table_index"],
            "country_slot": country_slot,
        })
        if not _valid_pointer(module_base):
            raise _Unknown("module_base_invalid")

        db_global = _add(module_base, DATABASE_GLOBAL_RVA, 8)
        db_pointer, db_raw = _read_qword(trace, db_global, "trade_power_sum.database_global.before")
        if not _valid_pointer(db_pointer) or db_pointer in (module_base, db_global):
            raise _Unknown("database_pointer_invalid")
        table_cell = _add(db_pointer, DATABASE_TABLE_OFFSET, 8)
        table_pointer, table_raw = _read_qword(trace, table_cell, "trade_power_sum.database_table.before")
        if (not _valid_pointer(table_pointer) or table_pointer in
                (module_base, db_global, db_pointer, table_cell) or table_pointer != identity["source_table_pointer"]):
            raise _Unknown("database_table_mismatch")
        table_entry = _add(table_pointer, country_slot * 8, 8)
        selected_pointer, selected_pointer_raw = _read_qword(
            trace, table_entry, "trade_power_sum.canonical_table_entry.before")
        if selected_pointer != identity["country_pointer"]:
            raise _Unknown("canonical_table_entry_mismatch")
        fullref_address = _add(identity["country_pointer"], COUNTRY_FULLREF_OFFSET, 8)
        selected_fullref_raw = trace.read(fullref_address, 8, "trade_power_sum.canonical_fullref.before")
        if selected_fullref_raw != identity["country_fullref_raw"]:
            raise _Unknown("canonical_fullref_mismatch")

        world_global = _add(module_base, WORLD_GLOBAL_RVA, 8)
        world_pointer, world_raw = _read_qword(trace, world_global, "trade_power_sum.world_global.before")
        if (not _valid_pointer(world_pointer) or world_pointer in
                (module_base, db_global, db_pointer, table_pointer, identity["country_pointer"])):
            raise _Unknown("world_pointer_invalid")
        list_cell = _add(world_pointer, WORLD_MEMBER_LIST_OFFSET, 8)
        count_cell = _add(world_pointer, WORLD_MEMBER_COUNT_OFFSET, 4)
        list_pointer, list_raw = _read_qword(trace, list_cell, "trade_power_sum.world_member_list.before")
        member_count, count_raw = _read_i32(trace, count_cell, "trade_power_sum.world_member_count.before")
        if not 1 <= member_count <= MAX_COUNTRY_SLOTS:
            raise _Unknown("member_count_out_of_range")
        list_bytes = member_count * 8
        if not _valid_pointer(list_pointer) or list_pointer in (
                module_base, db_global, db_pointer, table_pointer, identity["country_pointer"], world_pointer,
                list_cell, count_cell):
            raise _Unknown("member_list_pointer_invalid")
        if list_pointer + list_bytes - 1 > _trade.MAX_USER_ADDRESS:
            raise _Unknown("member_list_range_invalid")
        list_raw_before = trace.read(list_pointer, list_bytes, "trade_power_sum.members.before")

        aliases = {module_base, db_global, db_pointer, table_pointer, world_pointer,
                   list_pointer, list_cell, count_cell, table_cell, table_entry,
                   fullref_address, world_global}
        membership = {
            "member_count": member_count,
            "observer_occurrences": 0,
            "fullref_occurrences": 0,
            "slot_occurrences": 0,
            "selected_index": None,
            "members": [],
        }
        private["membership"] = membership
        seen_pointers: set[int] = set()
        observer_indices: list[int] = []
        fullref_indices: list[int] = []
        slot_indices: list[int] = []
        target_fullref_raw = identity["country_fullref_raw"]
        for index in range(member_count):
            start = index * 8
            pointer_raw = list_raw_before[start:start + 8]
            pointer = int.from_bytes(pointer_raw, "little", signed=False)
            if not _valid_pointer(pointer) or pointer in aliases or pointer in seen_pointers:
                raise _Unknown("member_pointer_invalid_or_aliased")
            seen_pointers.add(pointer)
            member_fullref_address = _add(pointer, COUNTRY_FULLREF_OFFSET, 8)
            if (member_fullref_address in aliases
                    and not (pointer == identity["country_pointer"]
                             and member_fullref_address == fullref_address)):
                raise _Unknown("member_fullref_alias")
            member_fullref_raw = trace.read(
                member_fullref_address, 8, f"trade_power_sum.member_fullref[{index}]")
            slot = int.from_bytes(member_fullref_raw[4:6], "little", signed=True)
            if not 0 <= slot < MAX_COUNTRY_SLOTS:
                raise _Unknown("member_slot_out_of_range")
            tag = _country_refs._tag_from_fullref(int.from_bytes(member_fullref_raw, "little"))
            member = {
                "index": index, "pointer": hex(pointer),
                "pointer_raw_hex": pointer_raw.hex(),
                "fullref_raw_hex": member_fullref_raw.hex(), "slot": slot, "tag": tag,
            }
            membership["members"].append(member)
            if pointer == identity["country_pointer"]:
                observer_indices.append(index)
            if member_fullref_raw == target_fullref_raw:
                fullref_indices.append(index)
            if slot == country_slot:
                slot_indices.append(index)
            membership["observer_occurrences"] = len(observer_indices)
            membership["fullref_occurrences"] = len(fullref_indices)
            membership["slot_occurrences"] = len(slot_indices)

        membership["observer_occurrences"] = len(observer_indices)
        membership["fullref_occurrences"] = len(fullref_indices)
        membership["slot_occurrences"] = len(slot_indices)
        if (len(observer_indices) != 1 or len(fullref_indices) != 1
                or len(slot_indices) != 1 or observer_indices[0] != fullref_indices[0]
                or observer_indices[0] != slot_indices[0]):
            raise _Unknown("observer_membership_not_unique")
        selected_index = observer_indices[0]
        membership["selected_index"] = selected_index
        private["membership"] = membership

        human_address = _add(world_pointer, WORLD_HUMAN_COUNT_OFFSET, 4)
        controllers_cell = _add(world_pointer, WORLD_CONTROLLERS_OFFSET, 8)
        human_count, human_raw = _read_i32(trace, human_address, "trade_power_sum.human_count.before")
        controllers_pointer, controllers_raw = _read_qword(
            trace, controllers_cell, "trade_power_sum.controllers_pointer.before")
        if (not _valid_pointer(controllers_pointer) or controllers_pointer in aliases
                or controllers_pointer in (list_pointer, identity["country_pointer"])):
            raise _Unknown("controllers_pointer_invalid")
        controller_address = _add(controllers_pointer, country_slot * CONTROLLER_I32_STRIDE, 4)
        controller_type, controller_raw = _read_i32(
            trace, controller_address, "trade_power_sum.observer_controller.before")

        anchors_before = {
            "database_global": db_raw.hex(), "database_table": table_raw.hex(),
            "canonical_table_entry": selected_pointer_raw.hex(),
            "canonical_fullref": selected_fullref_raw.hex(),
            "world_global": world_raw.hex(), "world_member_list": list_raw.hex(),
            "world_member_count": count_raw.hex(), "human_count": human_raw.hex(),
            "controllers_pointer": controllers_raw.hex(), "observer_controller": controller_raw.hex(),
            "member_list_bytes": list_raw_before.hex(),
        }

        db_pointer_after, db_raw_after = _read_qword(
            trace, db_global, "trade_power_sum.database_global.after")
        table_pointer_after, table_raw_after = _read_qword(
            trace, table_cell, "trade_power_sum.database_table.after")
        selected_pointer_after, selected_pointer_raw_after = _read_qword(
            trace, table_entry, "trade_power_sum.canonical_table_entry.after")
        selected_fullref_after = trace.read(fullref_address, 8, "trade_power_sum.canonical_fullref.after")
        world_pointer_after, world_raw_after = _read_qword(
            trace, world_global, "trade_power_sum.world_global.after")
        list_pointer_after, list_pointer_raw_after = _read_qword(
            trace, list_cell, "trade_power_sum.world_member_list.after")
        member_count_after, count_raw_after = _read_i32(
            trace, count_cell, "trade_power_sum.world_member_count.after")
        human_count_after, human_raw_after = _read_i32(
            trace, human_address, "trade_power_sum.human_count.after")
        controllers_pointer_after, controllers_raw_after = _read_qword(
            trace, controllers_cell, "trade_power_sum.controllers_pointer.after")
        controller_type_after, controller_raw_after = _read_i32(
            trace, controller_address, "trade_power_sum.observer_controller.after")
        member_list_raw_after = trace.read(list_pointer, list_bytes, "trade_power_sum.members.after")
        anchors_after = {
            "database_global": db_raw_after.hex(), "database_table": table_raw_after.hex(),
            "canonical_table_entry": selected_pointer_raw_after.hex(),
            "canonical_fullref": selected_fullref_after.hex(),
            "world_global": world_raw_after.hex(), "world_member_list": list_pointer_raw_after.hex(),
            "world_member_count": count_raw_after.hex(), "human_count": human_raw_after.hex(),
            "controllers_pointer": controllers_raw_after.hex(), "observer_controller": controller_raw_after.hex(),
            "member_list_bytes": member_list_raw_after.hex(),
        }
        stable = (
            db_pointer_after == db_pointer and table_pointer_after == table_pointer
            and selected_pointer_after == selected_pointer and selected_fullref_after == selected_fullref_raw
            and world_pointer_after == world_pointer and list_pointer_after == list_pointer
            and member_count_after == member_count and human_count_after == human_count
            and controllers_pointer_after == controllers_pointer and controller_type_after == controller_type
            and member_list_raw_after == list_raw_before
        )
        private.update({
            "database_pointer": hex(db_pointer), "table_pointer": hex(table_pointer),
            "world_pointer": hex(world_pointer), "controllers_pointer": hex(controllers_pointer),
            "role": {"human_count": human_count, "human_count_raw_hex": human_raw.hex(),
                     "controller_type": controller_type, "controller_raw_hex": controller_raw.hex(),
                     "controllers_pointer_raw_hex": controllers_raw.hex()},
            "anchors_before": anchors_before, "anchors_after": anchors_after,
            "stable": stable,
        })
        if not stable:
            raise _Unknown("anchors_changed")
        private["budget"] = {
            "calls": trace.calls, "bytes_requested": trace.bytes_requested,
            "max_calls": MAX_READ_CALLS, "max_bytes": MAX_TOTAL_READ,
            "max_single_read": MAX_SINGLE_READ,
        }
        return {
            "status": "observed", "basis": BASIS, "period": PERIOD, "complete": False,
            "stable": True,
            "country_slot": country_slot,
            "canonical_observer_verified": True,
            "observer_nonplayer_verified": human_count == 1 and controller_type == 0,
            "membership": membership,
            "raw_inputs": {"reads": trace.reads, **private},
        }
    except _Unknown as exc:
        if membership:
            private.setdefault("membership", membership)
        return _unknown(exc.reason, trace, private=private,
                        membership=membership or None, country_slot=country_slot)
    except Exception:
        return _unknown("internal_validation_error", trace, private=private,
                        membership=membership or None, country_slot=country_slot)

