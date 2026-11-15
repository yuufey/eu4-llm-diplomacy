"""Bounded reader for emperor/elector references in the current global HRE.

This leaf reads only the HRE object and its elector links.  It does not read
imperial influence, the six nearby flags, UI state, or invoke game code.  A
parent must bind process/session identity and replay the complete trace.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from . import country_reference_memory as _countries
from . import foreign_technology_capture as _owner


SCHEMA = "information.empire_memory.v1"
OBSERVER = "FRA"
WORLD_GLOBAL_RVA = 0x233FE58
WORLD_VTABLE_RVA = 0x1CB00C8
HRE_OFFSET = 0x15D0
HRE_VTABLE_RVA = 0x1CAFF08
MAX_ELECTOR_NODES = 64
MAX_READ_CALLS = 20_000
MAX_READ_BYTES = 512 * 1024
MAX_SINGLE_READ = 1024
_TAG = re.compile(r"[A-Z0-9]{3}\Z")


class EmpireMemoryError(ValueError):
    """The requested native HRE structure could not be bound safely."""


class _BudgetReader:
    def __init__(self, reader):
        self.reader = reader
        self.calls = 0
        self.bytes = 0
        self.max_single = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if (type(address) is not int or type(size) is not int or size <= 0
                or size > MAX_SINGLE_READ or address < 0x10000
                or address + size - 1 >= 0x800000000000):
            raise EmpireMemoryError("EMPIRE_READ_RANGE_INVALID")
        if self.calls + 1 > MAX_READ_CALLS or self.bytes + size > MAX_READ_BYTES:
            raise EmpireMemoryError("EMPIRE_READ_BUDGET_EXCEEDED")
        self.calls += 1
        self.bytes += size
        self.max_single = max(self.max_single, size)
        raw = self.reader.read(address, size, label)
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            raise EmpireMemoryError("EMPIRE_SHORT_READ")
        return bytes(raw)


def _pointer(value: Any, label: str) -> int:
    if (type(value) is not int or not 0x10000 <= value < 0x800000000000
            or value & 7):
        raise EmpireMemoryError(f"EMPIRE_POINTER_INVALID:{label}")
    return value


def _qword(reader, address: int, label: str) -> tuple[int, bytes]:
    raw = reader.read(address, 8, label)
    return int.from_bytes(raw, "little", signed=False), raw


def _fullref(raw: bytes, label: str) -> tuple[int, str]:
    if not isinstance(raw, bytes) or len(raw) != 8:
        raise EmpireMemoryError(f"EMPIRE_FULLREF_WIDTH:{label}")
    value = int.from_bytes(raw, "little", signed=False)
    tag = _countries._tag_from_fullref(value)
    if not isinstance(tag, str) or _TAG.fullmatch(tag) is None:
        raise EmpireMemoryError(f"EMPIRE_FULLREF_TAG_INVALID:{label}")
    return value, tag


def _read_elector_chain(reader, header: bytes, phase: str):
    if not isinstance(header, bytes) or len(header) != 24:
        raise EmpireMemoryError("EMPIRE_ELECTOR_HEADER_WIDTH")
    head = int.from_bytes(header[0:8], "little", signed=False)
    count = int.from_bytes(header[16:20], "little", signed=False)
    if count > MAX_ELECTOR_NODES:
        raise EmpireMemoryError("EMPIRE_ELECTOR_COUNT_OUT_OF_RANGE")
    if (count == 0) != (head == 0):
        raise EmpireMemoryError("EMPIRE_ELECTOR_HEAD_COUNT_MISMATCH")

    entries = []
    refs = []
    nodes: set[int] = set()
    fullrefs: set[int] = set()
    current = head
    for index in range(count):
        _pointer(current, f"elector_node_{index}")
        if current in nodes:
            raise EmpireMemoryError("EMPIRE_ELECTOR_CYCLE")
        nodes.add(current)
        raw_ref = reader.read(current, 8, f"empire.{phase}.electors[{index}].fullref")
        next_pointer, raw_next = _qword(
            reader, current + 0x10, f"empire.{phase}.electors[{index}].next")
        fullref, tag = _fullref(raw_ref, f"elector_{index}")
        if fullref in fullrefs:
            raise EmpireMemoryError("EMPIRE_ELECTOR_DUPLICATE_FULLREF")
        fullrefs.add(fullref)
        if next_pointer != 0 and next_pointer in nodes:
            raise EmpireMemoryError("EMPIRE_ELECTOR_CYCLE")
        if index + 1 < count:
            if next_pointer == 0:
                raise EmpireMemoryError("EMPIRE_ELECTOR_CHAIN_SHORT")
            _pointer(next_pointer, f"elector_next_{index}")
        elif next_pointer != 0:
            raise EmpireMemoryError("EMPIRE_ELECTOR_CHAIN_LONG")
        entries.append({
            "index": index,
            "node_address": hex(current),
            "fullref_raw_hex": raw_ref.hex(),
            "tag_candidate": tag,
            "next_raw_hex": raw_next.hex(),
        })
        refs.append((tag, fullref, raw_ref.hex()))
        current = next_pointer
    if current != 0:
        raise EmpireMemoryError("EMPIRE_ELECTOR_CHAIN_NOT_TERMINATED")
    return {
        "header_raw_hex": header.hex(),
        "head_raw_hex": header[0:8].hex(),
        "opaque_08_0f_raw_hex": header[8:16].hex(),
        "count_raw_hex": header[16:20].hex(),
        "opaque_14_17_raw_hex": header[20:24].hex(),
        "count": count,
        "entries": entries,
        "node_plus_8_read": False,
    }, refs


def _read_state(reader, module_base: int, observer: str, phase: str) -> dict[str, Any]:
    if observer != OBSERVER:
        raise EmpireMemoryError("EMPIRE_OBSERVER_SCOPE_INVALID")
    if type(module_base) is not int or module_base < 0x10000 or module_base & 7:
        raise EmpireMemoryError("EMPIRE_MODULE_BASE_INVALID")

    context_before = _owner._context(reader, module_base)
    world = _pointer(int(context_before["world_pointer"], 16), "world")
    world_global, world_global_raw = _qword(
        reader, module_base + WORLD_GLOBAL_RVA, f"empire.{phase}.world_global")
    if world_global != world:
        raise EmpireMemoryError("EMPIRE_WORLD_GLOBAL_CONTEXT_MISMATCH")
    world_vtable, world_vtable_raw = _qword(
        reader, world, f"empire.{phase}.world_vtable")
    if world_vtable != module_base + WORLD_VTABLE_RVA:
        raise EmpireMemoryError("EMPIRE_WORLD_VTABLE_MISMATCH")

    hre_address = _pointer(world + HRE_OFFSET, "hre_object")
    hre_vtable, hre_vtable_raw = _qword(
        reader, hre_address, f"empire.{phase}.hre_vtable")
    if hre_vtable != module_base + HRE_VTABLE_RVA:
        raise EmpireMemoryError("EMPIRE_HRE_VTABLE_MISMATCH")

    emperor_raw = reader.read(hre_address + 0x10, 8,
                              f"empire.{phase}.emperor_fullref")
    emperor_ref, emperor_tag = _fullref(emperor_raw, "emperor")
    header = reader.read(hre_address + 0x80, 24,
                         f"empire.{phase}.elector_header")
    elector_container, elector_refs = _read_elector_chain(reader, header, phase)

    physical_raw = bytes.fromhex(context_before["physical_client_reference_raw_hex"])
    physical_ref, physical_tag = _fullref(physical_raw, "physical_client")
    if physical_tag == observer:
        raise EmpireMemoryError("EMPIRE_OBSERVER_IS_PHYSICAL_PLAYER")

    expected: dict[str, int] = {physical_tag: physical_ref}
    requested = [observer, physical_tag]
    for tag, fullref, _raw_hex in [(emperor_tag, emperor_ref, emperor_raw.hex()), *elector_refs]:
        previous = expected.get(tag)
        if previous is not None and previous != fullref:
            raise EmpireMemoryError("EMPIRE_COUNTRY_FULLREF_CONFLICT")
        expected[tag] = fullref
        if tag not in requested:
            requested.append(tag)
    bindings = _countries.resolve_countries(
        reader.read, module_base, requested, expected_refs=expected)
    if bindings.get("status") != "observed" or bindings.get("basis") != "country_manager_table_tag_slot_binding":
        raise EmpireMemoryError("EMPIRE_COUNTRY_BINDING_UNAVAILABLE")
    resolved = bindings.get("requested")
    if not isinstance(resolved, dict):
        raise EmpireMemoryError("EMPIRE_COUNTRY_BINDING_SHAPE")
    if resolved[physical_tag].get("fullref_raw_hex") != physical_raw.hex():
        raise EmpireMemoryError("EMPIRE_PHYSICAL_CLIENT_REF_NOT_BOUND")
    if resolved[emperor_tag].get("fullref_raw_hex") != emperor_raw.hex():
        raise EmpireMemoryError("EMPIRE_EMPEROR_REF_NOT_BOUND")

    resolved_electors = []
    for index, (tag, fullref, raw_hex) in enumerate(elector_refs):
        row = resolved.get(tag)
        if not isinstance(row, dict) or row.get("fullref_raw_hex") != raw_hex:
            raise EmpireMemoryError("EMPIRE_ELECTOR_REF_NOT_BOUND")
        if int(row["fullref"], 16) != fullref:
            raise EmpireMemoryError("EMPIRE_ELECTOR_REF_VALUE_MISMATCH")
        resolved_electors.append({
            "index": index,
            "tag": tag,
            "fullref_raw_hex": raw_hex,
            "slot": row["slot"],
            "country_pointer": row["country_pointer"],
        })

    observer_row = resolved.get(observer)
    if not isinstance(observer_row, dict):
        raise EmpireMemoryError("EMPIRE_OBSERVER_COUNTRY_NOT_BOUND")
    human_raw = reader.read(world + 0xA60, 4, f"empire.{phase}.human_count")
    controller_pointer, controller_raw = _qword(
        reader, world + 0x1D48, f"empire.{phase}.controllers_pointer")
    _pointer(controller_pointer, "controllers")
    slot = observer_row.get("slot")
    if type(slot) is not int or not 0 <= slot < 4096:
        raise EmpireMemoryError("EMPIRE_OBSERVER_SLOT_INVALID")
    controller_raw_value = reader.read(
        controller_pointer + slot * 4, 4, f"empire.{phase}.observer_controller")
    human_count = int.from_bytes(human_raw, "little", signed=True)
    controller_type = int.from_bytes(controller_raw_value, "little", signed=True)
    if human_count != 1 or controller_type != 0:
        raise EmpireMemoryError("EMPIRE_OBSERVER_NOT_NONPLAYER")

    context_after = _owner._context(reader, module_base)
    if not _owner._same(context_before, context_after):
        raise EmpireMemoryError("EMPIRE_CONTEXT_CHANGED_WITHIN_PASS")
    return {
        "schema": SCHEMA,
        "status": "known",
        "observer": observer,
        "context_before": context_before,
        "context_after": context_after,
        "world_global_raw_hex": world_global_raw.hex(),
        "world_vtable_raw_hex": world_vtable_raw.hex(),
        "hre_address": hex(hre_address),
        "hre_vtable_raw_hex": hre_vtable_raw.hex(),
        "physical_client": {
            "tag": physical_tag,
            "fullref_raw_hex": physical_raw.hex(),
            "slot": resolved[physical_tag]["slot"],
            "country_pointer": resolved[physical_tag]["country_pointer"],
        },
        "observer_nonplayer": {
            "tag": observer,
            "slot": slot,
            "human_count": human_count,
            "controller_type": controller_type,
            "human_count_raw_hex": human_raw.hex(),
            "controller_type_raw_hex": controller_raw_value.hex(),
            "controllers_pointer_raw_hex": controller_raw.hex(),
            "verified": True,
            "basis": "copied_native_controller_array_not_hre_ui_visibility",
        },
        "emperor": {
            "tag": emperor_tag,
            "fullref_raw_hex": emperor_raw.hex(),
            "slot": resolved[emperor_tag]["slot"],
            "country_pointer": resolved[emperor_tag]["country_pointer"],
        },
        "elector_container": elector_container,
        "electors": resolved_electors,
        "country_bindings": bindings,
        "ui_visibility_evaluated": False,
    }


def read_state(reader, module_base: int, observer: str = OBSERVER) -> dict[str, Any]:
    """Read one non-atomic, bounded HRE snapshot from a supplied memory reader."""
    bounded = _BudgetReader(reader)
    state = _read_state(bounded, module_base, observer, "single")
    state["read_budget"] = {
        "calls": bounded.calls,
        "bytes_requested": bounded.bytes,
        "max_single_read": bounded.max_single,
        "limits": {"max_calls": MAX_READ_CALLS, "max_bytes": MAX_READ_BYTES,
                   "max_single_read": MAX_SINGLE_READ},
    }
    state["atomic_snapshot"] = False
    state["publication_admitted"] = False
    return state


__all__ = ["read_state", "EmpireMemoryError"]
