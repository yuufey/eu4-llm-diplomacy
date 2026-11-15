from __future__ import annotations

import pytest

from bridge.information import country_modifiers_memory as modifier_memory
from bridge.information import religious_scholars_memory as memory
from bridge.information import religious_schools_state_memory as school_state
from bridge.tests.test_information_country_modifiers_memory import ArchivedReader
from bridge.tests.test_information_religious_schools_memory import (
    DEFINITION, FULLREF, RELIGION, SCHOOL, TABLE_ENTRY, _qword,
)
from bridge.tests.test_information_religious_schools_state_memory import StateMemory


def _string32(key: bytes, *, storage: str, heap: int) -> bytes:
    header = bytearray(32)
    capacity = 15 if storage == "inline" else max(16, len(key))
    if storage == "inline":
        header[:len(key)] = key
        header[len(key)] = 0
    else:
        header[:8] = _qword(heap)
    header[16:24] = len(key).to_bytes(8, "little")
    header[24:32] = capacity.to_bytes(8, "little")
    return bytes(header)


class ScholarReader:
    """Join archived real direct modifiers to the actual 172 parent readers."""

    def __init__(self, *, secondary_keys=(), secondary_storage="inline",
                 empty_direct=False, secondary_error=None, parent_drift=None):
        self.archive = ArchivedReader()
        self.module_base = self.archive.module_base
        self.country_pointer = self.archive.country_pointer
        self.parent = StateMemory(has_school=True, flags=(1, 0))
        self.overrides: dict[str, list[bytes | BaseException]] = {}
        self.secondary_headers: list[bytes] = []
        self.secondary_payloads: list[bytes] = []
        self.secondary_error = secondary_error
        self.parent_drift = parent_drift
        self.calls: list[tuple[int, int, str]] = []

        # Keep the archived country and module identity for the real direct
        # modifier reader; adapt only the parent fixture's binding and bytes.
        self.parent.binding.update({
            "country_pointer": hex(self.country_pointer),
            "fullref": hex(FULLREF),
            "fullref_raw_hex": FULLREF.to_bytes(8, "little").hex(),
            "country_fullref_address": hex(self.country_pointer + 0x20),
            "table_entry_address": hex(TABLE_ENTRY),
            "table_entry_raw_hex": self.country_pointer.to_bytes(8, "little").hex(),
        })
        self.parent.regions[TABLE_ENTRY] = _qword(self.country_pointer)
        self.parent.regions[self.country_pointer + 0x20] = _qword(FULLREF)
        self.parent.regions[self.country_pointer + 0xF30] = _qword(RELIGION)
        self.parent.regions[self.country_pointer + 0x28B8] = _qword(SCHOOL)
        self.parent.regions[self.country_pointer + 0x220] = _qword(0)

        # The parent fixture's vtables are relative to its original base. Rebuild the
        # same native objects at the archived module base used by the modifier
        # profile so one call exercises both actual readers consistently.
        self.parent.regions[SCHOOL] = _qword(self.module_base + 0x1D21740)
        self.parent.regions[self.module_base + 0x1D21740 + 0x88] = _qword(
            self.module_base + 0x8F440)
        self.parent.regions[DEFINITION] = _qword(self.module_base + 0x1D216F8)
        self.parent.regions[self.module_base + 0x1D216F8 + 0x40] = _qword(
            self.module_base + 0xDACBC0)
        self.parent.regions[self.module_base + school_state.FLAG1_RVA] = b"\x01"
        self.parent.regions[self.module_base + school_state.FLAG2_RVA] = b"\x00"

        if empty_direct:
            layout = modifier_memory._profile_layout(modifier_memory._load_profile())
            self.archive.put(
                self.country_pointer + layout["country_list_head_offset"], _qword(0))

        self._add_secondary(
            list(secondary_keys), storage=secondary_storage,
            bad_type=secondary_error == "bad_type",
            cycle=secondary_error == "cycle")
        if secondary_error == "cap":
            self._add_secondary(
                [f"mod_{index}" for index in range(memory.MAX_SECONDARY + 1)],
                storage="inline")

    def _add_secondary(self, keys, *, storage="inline", bad_type=False, cycle=False):
        nodes = [0xB00000 + index * 0x100 for index in range(len(keys))]
        definitions = [0xC00000 + index * 0x200 for index in range(len(keys))]
        vtable = self.module_base + modifier_memory.DEFINITION_VTABLE_RVA
        for index, (key, node, definition) in enumerate(zip(keys, nodes, definitions)):
            next_node = nodes[index + 1] if index + 1 < len(nodes) else 0
            if cycle and index == len(nodes) - 1:
                next_node = node
            node_bytes = bytearray(0x18)
            node_bytes[:8] = _qword(definition)
            node_bytes[0x10:0x18] = _qword(next_node)
            self.parent.regions[node] = bytes(node_bytes)

            definition_bytes = bytearray(0x178)
            definition_bytes[:8] = _qword(vtable + (8 if bad_type and index == 0 else 0))
            heap = 0xD00000 + index * 0x200
            header = _string32(key.encode("ascii"), storage=storage, heap=heap)
            definition_bytes[0x158:0x178] = header
            self.parent.regions[definition] = bytes(definition_bytes)
            self.secondary_headers.append(header)
            if storage == "heap":
                payload = key.encode("ascii") + b"\0"
                self.parent.regions[heap] = payload
                self.secondary_payloads.append(payload)
        head = nodes[0] if nodes else 0
        self.parent.regions[self.country_pointer + 0x220] = _qword(head)

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls.append((address, size, label))
        scripted = self.overrides.get(label)
        if scripted:
            value = scripted.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value
        if (self.secondary_error == "shared_budget"
                and label.startswith("religious_scholars.country_modifiers.")):
            raise ValueError("shared_read_budget_exceeded")
        if (self.parent_drift is not None
                and label.startswith("religious_scholars.school_state.")
                and self.parent_drift in label and label.endswith("_scholar_after")):
            original = self.parent.read(address, size, label)
            changed = bytearray(original)
            changed[0] ^= 1
            return bytes(changed)
        if label.startswith("religious_scholars.country_modifiers."):
            return self.archive.read(address, size, label)
        return self.parent.read(address, size, label)


def _read(reader: ScholarReader):
    return memory.read_fields(reader, reader.module_base, reader.parent.binding,
                              (memory.FIELD_ID,))[memory.FIELD_ID]


def _known(reader: ScholarReader) -> dict:
    field = _read(reader)
    assert field["status"] == "known"
    assert field["complete"] is False
    return field


def _assert_child_unknown(field: dict, reason: str) -> None:
    assert field["status"] == "known"
    child = field["value"]["invited_scholars"]
    assert child == {"status": "unknown", "reason": reason}
    assert field["value"]["has_school"] is True
    assert field["value"]["current_school"] == {"status": "known", "key": "shafi"}


def test_both_modifier_lists_empty_is_a_known_complete_membership_snapshot():
    field = _known(ScholarReader(empty_direct=True))

    assert field["value"]["invited_scholars"] == {
        "status": "known", "membership_complete": True, "modifier_instances": []}


def test_direct_and_secondary_instances_keep_their_native_source_fields():
    reader = ScholarReader(secondary_keys=["secondary"])
    field = _known(reader)
    child = field["value"]["invited_scholars"]
    direct = field["raw_inputs"]["direct_record"]["fields"]["modifiers"]["value"]

    assert set(child) == {"status", "membership_complete", "modifier_instances"}
    assert child["status"] == "known"
    assert child["membership_complete"] is True
    assert child["modifier_instances"][:len(direct)] == [
        {"source": "direct", "key": item["key"],
         "start_date_raw": item["start_date_raw"], "date_raw": item["date_raw"],
         "flags": item["flags"]}
        for item in direct
    ]
    assert [item["key"] for item in direct] == [
        "papal_sanction_for_church_taxes", "shady_people"]
    assert all(type(item["start_date_raw"]) is int and type(item["date_raw"]) is int
               for item in child["modifier_instances"][:len(direct)])
    assert all(all(type(flag) is int and 0 <= flag <= 255
                   for flag in item["flags"].values())
               for item in child["modifier_instances"][:len(direct)])
    assert child["modifier_instances"][-1] == {
        "source": "secondary", "key": "secondary",
        "start_date_raw": None, "date_raw": None, "flags": None}


def test_secondary_heap_key_uses_real_string32_pointer_payload_and_terminator():
    key = "secondary_scholar_trait_long"
    field = _known(ScholarReader(
        secondary_keys=[key], secondary_storage="heap"))
    child = field["value"]["invited_scholars"]
    rows = {row["label"]: row for row in field["raw_inputs"]["reads"]}
    header = bytes.fromhex(
        rows["religious_scholars.secondary.definition_0.key_header"]["raw_hex"])
    payload_row = rows["religious_scholars.secondary.definition_0.key_payload"]
    payload = bytes.fromhex(payload_row["raw_hex"])
    length = int.from_bytes(header[16:24], "little")
    capacity = int.from_bytes(header[24:32], "little")
    heap_pointer = int.from_bytes(header[:8], "little")

    assert child["modifier_instances"][-1] == {
        "source": "secondary", "key": key,
        "start_date_raw": None, "date_raw": None, "flags": None}
    assert capacity >= 16 and length == len(key.encode("ascii"))
    assert payload_row["address"] == hex(heap_pointer)
    assert len(payload) == length + 1 and payload[:length] == key.encode("ascii")
    assert payload[length] == 0 and b"\0" not in payload[:length]


def test_direct_reader_failure_only_makes_the_scholar_child_unknown():
    reader = ScholarReader(secondary_keys=["secondary"])
    reader.overrides["religious_scholars.country_modifiers.list_head"] = [
        OSError("direct list unavailable")]

    field = _known(reader)

    _assert_child_unknown(field, "SCHOLAR_MODIFIERS_UNAVAILABLE")


@pytest.mark.parametrize(("failure", "detail"), [
    ("bad_type", "secondary_definition_type_invalid"),
    ("cycle", "secondary_modifier_list_cycle_or_over_bound"),
    ("cap", "secondary_modifier_list_cycle_or_over_bound"),
])
def test_secondary_invalid_type_cycle_or_cap_only_makes_scholar_child_unknown(
        failure, detail):
    keys = ["secondary"] if failure != "cap" else []
    reader = ScholarReader(secondary_keys=keys, secondary_error=failure)

    field = _known(reader)

    _assert_child_unknown(field, "SCHOLAR_MODIFIERS_UNAVAILABLE")
    assert field["raw_inputs"]["modifier_error"]["detail"] == detail


@pytest.mark.parametrize("change", [
    "direct_list", "secondary_list", "secondary_definition", "inline_header", "heap_payload",
])
def test_modifier_list_definition_header_or_heap_drift_only_revokes_child(change):
    storage = "heap" if change == "heap_payload" else "inline"
    reader = ScholarReader(
        secondary_keys=[] if change == "direct_list" else [
            "secondary_scholar_trait_long" if storage == "heap" else "secondary_trait"],
        secondary_storage=storage)
    if change == "direct_list":
        label, replacement = (
            "religious_scholars.country_modifiers.list_head_scholar_after", _qword(0))
    elif change == "secondary_list":
        label, replacement = "religious_scholars.secondary.head_scholar_after", _qword(0)
    elif change == "secondary_definition":
        label, replacement = (
            "religious_scholars.secondary.node_0.definition_scholar_after", _qword(0xE00000))
    elif change == "inline_header":
        label = "religious_scholars.secondary.definition_0.key_header_scholar_after"
        mutated = bytearray(reader.secondary_headers[0])
        mutated[0] ^= 1
        replacement = bytes(mutated)
    else:
        label = "religious_scholars.secondary.definition_0.key_payload_scholar_after"
        original = reader.secondary_payloads[0]
        mutated = bytearray(original)
        mutated[0] ^= 1
        replacement = bytes(mutated)
    reader.overrides[label] = [replacement]

    field = _known(reader)

    _assert_child_unknown(field, "SCHOLAR_MODIFIERS_CHANGED")


@pytest.mark.parametrize("parent_change", ["school_pointer", "primary_religion_pointer"])
def test_parent_school_or_religion_identity_drift_revokes_whole_field(parent_change):
    reader = ScholarReader(parent_drift=parent_change)

    field = _read(reader)

    assert field["status"] == "unknown"
    assert field["complete"] is False
    assert "value" not in field
    assert "scholar_parent_changed" in field["reason"]


def test_parent_owned_shared_budget_failure_caught_by_modifier_reader_bubbles():
    reader = ScholarReader(secondary_error="shared_budget")

    with pytest.raises(ValueError, match="scholar_shared_read_budget_exceeded"):
        _read(reader)


def test_local_budget_failure_caught_by_modifier_reader_bubbles(monkeypatch):
    probe = ScholarReader(secondary_keys=["secondary"])
    parent_field = _known(probe)
    parent_bytes = parent_field["raw_inputs"]["parent"]["raw_inputs"]["budget"][
        "bytes_requested"]

    monkeypatch.setattr(memory, "MAX_READ_BYTES", parent_bytes)
    reader = ScholarReader(secondary_keys=["secondary"])

    with pytest.raises(ValueError, match="scholar_shared_read_budget_exceeded"):
        _read(reader)

