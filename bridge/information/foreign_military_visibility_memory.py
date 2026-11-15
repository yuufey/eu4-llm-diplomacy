"""Bounded private reader for the native diplomatic military-stats gate.

The parent is responsible for installation/session identity, complete country
binding scans, and observer role admission.  This leaf rechecks the supplied
FRA and target references, then projects the saved native permission rule.  It
does not call game code or establish public visibility by itself.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import country_scale_development_memory as _country_scale


SCHEMA = "information.foreign_military_visibility_memory.v1"
OBSERVER_TAG = "FRA"

WORLD_GLOBAL_RVA = 0x233FE58
WORLD_SETTINGS_OFFSET = 0x2150
PUBLIC_OPTIONS_OFFSET = 0x5C
PUBLIC_OPTIONS_SECOND_OFFSET = 0x28
WORLD_DATE_OFFSET = 0x1DD0

TARGET_TIMED_HEAD_OFFSET = 0x238
NODE_RECORD_POINTER_OFFSET = 0x0
NODE_NEXT_POINTER_OFFSET = 0x10
RECORD_OBSERVER_FULLREF_OFFSET = 0x10
RECORD_EXPIRY_DATE_OFFSET = 0x18
MAX_NODES = 256
MAX_CALLS = 2048
MAX_TOTAL_BYTES = 64 * 1024
MAX_SINGLE_READ_BYTES = 8192
MAX_USER_ADDRESS = _country_scale.MAX_USER_ADDRESS_EXCLUSIVE
MIN_USER_ADDRESS = _country_scale.MIN_USER_ADDRESS
MAX_U64 = 0xFFFFFFFFFFFFFFFF


class _Unknown(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _checked_add(base: int, offset: int) -> int:
    if (type(base) is not int or not MIN_USER_ADDRESS <= base < MAX_USER_ADDRESS
            or type(offset) is not int or offset < 0 or base > MAX_U64 - offset):
        raise _Unknown("ADDRESS_INVALID")
    result = base + offset
    if not MIN_USER_ADDRESS <= result < MAX_USER_ADDRESS:
        raise _Unknown("ADDRESS_INVALID")
    return result


def _signed_i16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


class _TraceReader:
    def __init__(self, reader: Any) -> None:
        method = getattr(reader, "read", None)
        self._read = method if callable(method) else reader if callable(reader) else None
        self.reads: list[dict[str, Any]] = []
        self.calls = 0
        self.bytes_requested = 0

    def exact(self, address: int, size: int, label: str) -> bytes:
        if self._read is None:
            raise _Unknown("READER_INVALID")
        if (type(size) is not int or size <= 0 or size > MAX_SINGLE_READ_BYTES
                or type(address) is not int or address < MIN_USER_ADDRESS
                or address > MAX_U64 - (size - 1)
                or address + size - 1 >= MAX_USER_ADDRESS):
            raise _Unknown("ADDRESS_INVALID")
        if self.calls + 1 > MAX_CALLS or self.bytes_requested + size > MAX_TOTAL_BYTES:
            self.reads.append({"address": hex(address), "size": size, "label": label,
                               "status": "rejected", "reason": "READ_BUDGET_EXCEEDED"})
            raise _Unknown("READ_BUDGET_EXCEEDED")
        self.calls += 1
        self.bytes_requested += size
        try:
            raw = self._read(address, size, label)
        except Exception as exc:
            self.reads.append({"address": hex(address), "size": size, "label": label,
                               "status": "failed", "error_type": type(exc).__name__})
            raise _Unknown("READ_FAILED") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            self.reads.append({"address": hex(address), "size": size, "label": label,
                               "status": "failed", "error_type": "SHORT_OR_INVALID_READ"})
            raise _Unknown("READ_FAILED")
        data = bytes(raw)
        self.reads.append({"address": hex(address), "size": size, "label": label,
                           "status": "ok", "raw_hex": data.hex()})
        return data

    def read(self, address: int, size: int, label: str) -> bytes:
        return self.exact(address, size, label)

    def u64(self, address: int, label: str) -> int:
        return int.from_bytes(self.exact(address, 8, label), "little", signed=False)

    def i32(self, address: int, label: str) -> int:
        return int.from_bytes(self.exact(address, 4, label), "little", signed=True)

    def summary(self) -> dict[str, int]:
        return {"calls": self.calls, "bytes_requested": self.bytes_requested,
                "call_limit": MAX_CALLS, "byte_limit": MAX_TOTAL_BYTES,
                "single_read_limit": MAX_SINGLE_READ_BYTES}


def _private_inputs(observer: Mapping[str, Any] | None,
                    target: Mapping[str, Any] | None,
                    trace: _TraceReader,
                    details: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result = {
        "observer_binding": None if observer is None else {
            "tag": observer["tag"], "slot": observer["slot"],
            "country_pointer": hex(observer["country_pointer"]),
            "fullref": hex(observer["fullref"]),
            "fullref_raw_hex": observer["fullref_raw_hex"],
        },
        "target_binding": None if target is None else {
            "tag": target["tag"], "slot": target["slot"],
            "country_pointer": hex(target["country_pointer"]),
            "fullref": hex(target["fullref"]),
            "fullref_raw_hex": target["fullref_raw_hex"],
        },
        "reads": list(trace.reads),
        "budget": trace.summary(),
    }
    if details:
        result.update(dict(details))
    return result


def _binding_failure_reason(trace: _TraceReader, role: str) -> str:
    last = trace.reads[-1] if trace.reads else None
    if isinstance(last, Mapping):
        if last.get("status") == "rejected" and last.get("reason") == "READ_BUDGET_EXCEEDED":
            return "READ_BUDGET_EXCEEDED"
        if last.get("status") == "failed":
            return "READ_FAILED"
    return f"{role}_BINDING_DATABASE_MISMATCH"


def _known(admitted: bool, mode: str, observer: Mapping[str, Any],
           target: Mapping[str, Any], trace: _TraceReader,
           details: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "known",
        "admitted": admitted,
        "mode": mode,
        "observer": {"tag": observer["tag"], "slot": observer["slot"]},
        "target": {"tag": target["tag"], "slot": target["slot"]},
        "raw_inputs": {**_private_inputs(observer, target, trace), **dict(details)},
    }


def read_permission(reader: Any, base: int, observer_binding: Any,
                    target_binding: Any) -> dict[str, Any]:
    """Project the native observer-to-target military-stats permission test.

    The caller must already have validated the fixed build/session, completed
    country-manager scan, and FRA non-player role.  This leaf rechecks only
    the two supplied country slots and never scans the full table.
    """
    trace = _TraceReader(reader)
    observer: dict[str, Any] | None = None
    target: dict[str, Any] | None = None
    details: dict[str, Any] = {}
    try:
        if type(base) is not int or not MIN_USER_ADDRESS <= base < MAX_USER_ADDRESS or base & 7:
            raise _Unknown("MODULE_BASE_INVALID")

        try:
            parsed_base, observer_pointer, observer_row = _country_scale._parse_target(
                base, observer_binding)
        except Exception as exc:
            raise _Unknown("OBSERVER_BINDING_INVALID") from exc
        if parsed_base != base:
            raise _Unknown("OBSERVER_BINDING_INVALID")
        if observer_row.get("tag") != OBSERVER_TAG:
            raise _Unknown("OBSERVER_NOT_FRA")
        try:
            parsed_base, target_pointer, target_row = _country_scale._parse_target(
                base, target_binding)
        except Exception as exc:
            raise _Unknown("TARGET_BINDING_INVALID") from exc
        if parsed_base != base:
            raise _Unknown("TARGET_BINDING_INVALID")

        observer_ref = int(observer_row["fullref"], 0)
        target_ref = int(target_row["fullref"], 0)
        observer = {
            "tag": observer_row["tag"], "slot": observer_row["slot"],
            "country_pointer": observer_pointer, "fullref": observer_ref,
            "fullref_raw_hex": observer_row["fullref_raw_hex"],
        }
        target = {
            "tag": target_row["tag"], "slot": target_row["slot"],
            "country_pointer": target_pointer, "fullref": target_ref,
            "fullref_raw_hex": target_row["fullref_raw_hex"],
        }
        if observer_pointer == target_pointer and observer_ref != target_ref:
            raise _Unknown("BINDING_ALIAS")
        try:
            details["observer_binding_validation"] = _country_scale._validate_target_binding(
                trace, base, observer_pointer, observer_row)
        except Exception as exc:
            raise _Unknown(_binding_failure_reason(trace, "OBSERVER")) from exc
        try:
            details["target_binding_validation"] = _country_scale._validate_target_binding(
                trace, base, target_pointer, target_row)
        except Exception as exc:
            raise _Unknown(_binding_failure_reason(trace, "TARGET")) from exc

        global_address = _checked_add(base, WORLD_GLOBAL_RVA)
        world = trace.u64(global_address, "world.global_pointer")
        if (world < MIN_USER_ADDRESS or world >= MAX_USER_ADDRESS or world & 7
                or world in (base, observer_pointer, target_pointer)):
            raise _Unknown("WORLD_POINTER_INVALID")
        details["world"] = {"global_address": hex(global_address), "pointer": hex(world)}

        settings_address = _checked_add(world, WORLD_SETTINGS_OFFSET)
        settings = trace.u64(settings_address, "world.settings_pointer")
        if (settings < MIN_USER_ADDRESS or settings >= MAX_USER_ADDRESS or settings & 7
                or settings in (base, world, observer_pointer, target_pointer)):
            raise _Unknown("SETTINGS_POINTER_INVALID")
        details["settings"] = {"address": hex(settings_address), "pointer": hex(settings)}

        public_a_address = _checked_add(settings, PUBLIC_OPTIONS_OFFSET)
        public_b_address = _checked_add(settings, PUBLIC_OPTIONS_SECOND_OFFSET)
        public_a = trace.i32(public_a_address, "settings.public_options_primary")
        public_b = trace.i32(public_b_address, "settings.public_options_secondary")
        details["public_options"] = {
            "primary": {"address": hex(public_a_address), "value": public_a,
                        "raw_hex": (public_a & 0xFFFFFFFF).to_bytes(4, "little").hex()},
            "secondary": {"address": hex(public_b_address), "value": public_b,
                          "raw_hex": (public_b & 0xFFFFFFFF).to_bytes(4, "little").hex()},
        }
        if public_a == 0 and public_b == 0:
            return _known(True, "public_options", observer, target, trace, details)

        head_address = _checked_add(target_pointer, TARGET_TIMED_HEAD_OFFSET)
        node = trace.u64(head_address, "target.timed_entry_head")
        details["timed_entry_head"] = {"address": hex(head_address), "pointer": hex(node)}
        if node == 0:
            return _known(False, "no_timed_entry", observer, target, trace, details)

        seen: set[int] = set()
        entries: list[dict[str, Any]] = []
        observer_slot = _signed_i16(observer["fullref"] >> 32)
        nodes_read = 0
        while node != 0:
            if node < MIN_USER_ADDRESS or node >= MAX_USER_ADDRESS or node & 7:
                raise _Unknown("TIMED_NODE_POINTER_INVALID")
            if node in seen:
                raise _Unknown("TIMED_LIST_CYCLE")
            if nodes_read >= MAX_NODES:
                raise _Unknown("TIMED_LIST_LIMIT_EXCEEDED")
            if node in (base, world, settings, observer_pointer, target_pointer):
                raise _Unknown("TIMED_NODE_ALIAS")
            seen.add(node)
            nodes_read += 1

            record_address = _checked_add(node, NODE_RECORD_POINTER_OFFSET)
            next_address = _checked_add(node, NODE_NEXT_POINTER_OFFSET)
            record = trace.u64(record_address, f"timed_node[{nodes_read - 1}].record")
            next_node = trace.u64(next_address, f"timed_node[{nodes_read - 1}].next")
            entry: dict[str, Any] = {
                "node": hex(node), "record_pointer": hex(record),
                "next_pointer": hex(next_node),
            }
            entries.append(entry)
            details["timed_entries"] = entries

            if record < MIN_USER_ADDRESS or record >= MAX_USER_ADDRESS or record & 7:
                raise _Unknown("TIMED_RECORD_POINTER_INVALID")
            if record in (base, world, settings, observer_pointer,
                          target_pointer, node, next_node):
                raise _Unknown("TIMED_RECORD_ALIAS")
            record_ref_address = _checked_add(record, RECORD_OBSERVER_FULLREF_OFFSET)
            record_ref = trace.u64(record_ref_address,
                                   f"timed_node[{nodes_read - 1}].record_fullref")
            entry["record_fullref"] = {
                "address": hex(record_ref_address), "value": hex(record_ref),
                "raw_hex": record_ref.to_bytes(8, "little").hex(),
                "signed_slot": _signed_i16(record_ref >> 32),
            }
            if _signed_i16(record_ref >> 32) == observer_slot:
                if record_ref != observer["fullref"]:
                    raise _Unknown("MATCHED_OBSERVER_FULLREF_MISMATCH")
                date_address = _checked_add(world, WORLD_DATE_OFFSET)
                game_date = trace.i32(date_address, "world.game_date")
                expiry_address = _checked_add(record, RECORD_EXPIRY_DATE_OFFSET)
                expiry = trace.i32(expiry_address,
                                   f"timed_node[{nodes_read - 1}].expiry_date")
                entry["expiry_date"] = {
                    "address": hex(expiry_address), "value": expiry,
                    "raw_hex": (expiry & 0xFFFFFFFF).to_bytes(4, "little").hex(),
                }
                details["game_date"] = {
                    "address": hex(date_address), "value": game_date,
                    "raw_hex": (game_date & 0xFFFFFFFF).to_bytes(4, "little").hex(),
                }
                admitted = game_date < expiry
                mode = "active_timed_entry" if admitted else "expired_timed_entry"
                return _known(admitted, mode, observer, target, trace, details)
            node = next_node

        return _known(False, "no_timed_entry", observer, target, trace, details)
    except _Unknown as exc:
        return {
            "schema": SCHEMA,
            "status": "unknown",
            "reason": exc.reason,
            "private_inputs": _private_inputs(observer, target, trace, details),
        }
    except Exception:
        return {
            "schema": SCHEMA,
            "status": "unknown",
            "reason": "INTERNAL_READ_FAILURE",
            "private_inputs": _private_inputs(observer, target, trace, details),
        }


__all__ = ["SCHEMA", "read_permission"]
