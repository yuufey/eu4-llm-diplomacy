"""Offline boundary tests for the passive province-power calculation gates."""
from __future__ import annotations

import struct

import pytest

from bridge.information import province_identity_memory as identity
from bridge.information import province_trade_power_gates_memory as gates
from bridge.tests import test_information_province_state_memory as fixture

BASE = fixture.BASES[0]
PROVINCE_ID = fixture.PROVINCE_ID
RECORD = fixture.RECORDS + PROVINCE_ID * identity.PROVINCE_RECORD_STRIDE
NODE = 0x5D00000000
VTABLE = BASE + 0x100000
METHOD = BASE + 0x200000
CONTROLLER_TYPE = 0x6200000000
CONTAINER = 0x6300000000
VECTOR = 0x6400000000
ENTRY_BASE = 0x6500000000
GLOBAL_BONUS_RVA = 0x233F418


def _binding(tag: str) -> dict:
    slot = fixture.COUNTRY_TAG_SLOTS[tag]
    pointer = fixture.COUNTRY_BASE + slot * 0x1000
    fullref = fixture._fullref(tag, slot)
    return {
        "tag": tag, "slot": slot, "country_pointer": hex(pointer),
        "fullref": hex(fullref), "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
    }


def _province_binding() -> dict:
    return {
        "province_id": PROVINCE_ID, "record_id": PROVINCE_ID,
        "record_pointer": hex(RECORD),
        "id_address": hex(RECORD + identity.PROVINCE_ID_OFFSET),
        "id_raw_hex": struct.pack("<i", PROVINCE_ID).hex(),
    }


class MemoryImage:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.fail_labels: set[str] = set()
        self.mutate_on: dict[str, tuple[int, int, bytes]] = {}
        self.seen: dict[str, int] = {}

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + offset: byte for offset, byte in enumerate(raw)})

    def put_u8(self, address: int, value: int) -> None:
        self.put(address, bytes([value & 0xFF]))

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label in self.fail_labels:
            raise OSError("synthetic read failure")
        self.seen[label] = self.seen.get(label, 0) + 1
        mutation = self.mutate_on.get(label)
        if mutation is not None and self.seen[label] == mutation[0]:
            self.put(mutation[1], mutation[2])
        try:
            return bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError(f"unmapped synthetic read:{label}") from exc


def _image(*, node_pointer: int = NODE, predicate: bytes = b"\xb0\x01\xc3",
           controller_enabled: bool = True, flags: int = 0,
           owner_entries: list[tuple[int, int]] | None = None,
           empty_container: bool = False) -> MemoryImage:
    image = MemoryImage()
    controller = _binding("SWE")
    owner = _binding("ENG")
    image.put(RECORD + 0x470, bytes.fromhex(controller["fullref_raw_hex"]))
    image.put(RECORD + 0x468, bytes.fromhex(owner["fullref_raw_hex"]))
    image.put_u64(RECORD + 0xE8, node_pointer)
    image.put_u8(RECORD + 0x958, flags)
    if node_pointer:
        image.put_u64(NODE, VTABLE)
        image.put_u64(VTABLE + 0x40, METHOD)
        image.put(METHOD, predicate)
    image.put_u64(int(controller["country_pointer"], 0) + 0x2440, CONTROLLER_TYPE)
    image.put_u8(CONTROLLER_TYPE + 0x79, int(controller_enabled))
    if flags & 4:
        image.put_u64(RECORD + 0x8A8, CONTAINER)
        entries = owner_entries or []
        begin = 0 if empty_container else (VECTOR if entries else 0)
        end = 0 if empty_container else (VECTOR + 8 * len(entries) if entries else 0)
        image.put_u64(CONTAINER + 0x28, begin)
        image.put_u64(CONTAINER + 0x30, end)
        for index, (fullref, flag40) in enumerate(entries):
            entry = ENTRY_BASE + index * 0x400
            image.put_u64(VECTOR + index * 8, entry)
            image.put_u64(entry + 0x1C0, fullref)
            image.put_u8(entry + 0x40, flag40)
        image.put_i32(BASE + GLOBAL_BONUS_RVA, 500)
    return image


_DEFAULT_OWNER = object()


def _read(image: MemoryImage, *, owner: dict | None = _DEFAULT_OWNER,
          controller: dict | None = None) -> dict:
    if owner is _DEFAULT_OWNER:
        owner = _binding("ENG")
    return gates.read_fields(image, BASE, _province_binding(),
                             controller or _binding("SWE"), owner)[gates.FIELD]


def _value(*, node=False, controller=None, bonus=None, raw=None):
    return {
        "province_node_enabled": node,
        "controller_type_enabled": controller,
        "owner_bonus_active": bonus,
        "owner_bonus_raw": raw,
    }


def test_null_province_runtime_is_a_known_zero_branch_without_following_pointer():
    image = _image(node_pointer=0, flags=4)

    field = _read(image)

    assert field["status"] == "known"
    assert field["value"] == _value()
    assert "province_trade_gates.node_vtable" not in [label for _, _, label in image.reads]
    assert "province_trade_gates.owner_ref" not in [label for _, _, label in image.reads]


def test_constant_false_predicate_is_decoded_and_returns_before_country_gate():
    image = _image(predicate=b"\xb0\x00\xc3", flags=4)

    field = _read(image)

    assert field["status"] == "known"
    assert field["value"] == _value(node=False)
    labels = [label for _, _, label in image.reads]
    assert "province_trade_gates.node_predicate_code" in labels
    assert not any("controller_type" in label or "owner_ref" in label for label in labels)


def test_disabled_controller_type_is_a_known_zero_branch():
    image = _image(controller_enabled=False, flags=4)

    field = _read(image)

    assert field["status"] == "known"
    assert field["value"] == _value(node=True, controller=False)
    labels = [label for _, _, label in image.reads]
    assert "province_trade_gates.controller_type_flag79" in labels
    assert "province_trade_gates.province_flags958" not in labels
    assert "province_trade_gates.owner_ref" not in labels


def test_clear_owner_bonus_flag_does_not_resolve_owner():
    image = _image(flags=0)

    field = _read(image)

    assert field["status"] == "known"
    assert field["value"] == _value(node=True, controller=True, bonus=False, raw=0)
    assert "province_trade_gates.province_flags958" in [label for _, _, label in image.reads]
    assert not any("owner_" in label for _, _, label in image.reads)


def test_first_admitted_owner_entry_reports_signed_bonus_500():
    owner_ref = fixture._fullref("ENG", fixture.COUNTRY_TAG_SLOTS["ENG"])
    image = _image(flags=4, owner_entries=[(owner_ref, 1)])

    field = _read(image)

    assert field["status"] == "known"
    assert field["value"] == _value(node=True, controller=True, bonus=True, raw=500)
    assert "province_trade_gates.owner_bonus_global" in [label for _, _, label in image.reads]


def test_first_matching_entry_with_clear_flag_wins_over_later_matching_entry():
    owner_ref = fixture._fullref("ENG", fixture.COUNTRY_TAG_SLOTS["ENG"])
    image = _image(flags=4, owner_entries=[(owner_ref, 0), (owner_ref, 1)])

    field = _read(image)

    assert field["status"] == "known"
    assert field["value"] == _value(node=True, controller=True, bonus=False, raw=0)
    labels = [label for _, _, label in image.reads]
    assert labels.count("province_trade_gates.owner_first_match_flag40") == 2
    assert "province_trade_gates.owner_entry_1_ref" not in labels
    assert "province_trade_gates.owner_bonus_global" not in labels


@pytest.mark.parametrize("empty", [False, True])
def test_no_matching_entry_or_empty_vector_is_a_known_inactive_bonus(empty: bool):
    image = _image(flags=4, owner_entries=[] if empty else [
        (fixture._fullref("FRA", fixture.COUNTRY_TAG_SLOTS["FRA"]), 1),
        (fixture._fullref("SWE", fixture.COUNTRY_TAG_SLOTS["SWE"]), 1),
    ], empty_container=empty)

    field = _read(image)

    assert field["status"] == "known"
    assert field["value"] == _value(node=True, controller=True, bonus=False, raw=0)
    labels = [label for _, _, label in image.reads]
    assert "province_trade_gates.owner_bonus_global" not in labels
    if empty:
        assert "province_trade_gates.owner_entries_begin" in labels
        assert not any("owner_entry_" in label for label in labels)
    else:
        assert "province_trade_gates.owner_entry_1_ref" in labels


def test_same_owner_slot_with_different_fullref_is_rejected():
    eng_slot = fixture.COUNTRY_TAG_SLOTS["ENG"]
    stale_ref = fixture._fullref("ENG", eng_slot, generation=0x1201)
    image = _image(flags=4, owner_entries=[(stale_ref, 1)])

    field = _read(image)

    assert field["status"] == "unknown"
    assert field["reason"] == "OWNER_ENTRY_REFERENCE_MISMATCH"
    assert "value" not in field


def test_controller_and_owner_binding_references_must_match_province_references():
    image = _image(flags=0)
    wrong_controller = _binding("FRA")
    wrong_owner = _binding("FRA")

    controller_field = _read(image, controller=wrong_controller)
    owner_mismatch_image = _image(flags=4, owner_entries=[])
    owner_field = _read(owner_mismatch_image, owner=wrong_owner)

    assert controller_field["status"] == "unknown"
    assert controller_field["reason"] == "CONTROLLER_REFERENCE_CHANGED"
    assert owner_field["status"] == "unknown"
    assert owner_field["reason"] == "OWNER_REFERENCE_CHANGED"


def test_owner_admission_is_required_only_when_owner_bonus_flag_is_set():
    no_owner = _read(_image(flags=0), owner=None)
    required_owner = _read(_image(flags=4, owner_entries=[]), owner=None)

    assert no_owner["status"] == "known"
    assert no_owner["value"] == _value(node=True, controller=True, bonus=False, raw=0)
    assert required_owner["status"] == "unknown"
    assert required_owner["reason"] == "OWNER_ADMISSION_NOT_ESTABLISHED"


@pytest.mark.parametrize(("predicate", "reason"), [
    (b"\x90\x90\xc3", "NODE_PREDICATE_UNSUPPORTED"),
    (b"\xb0\x02\xc3", "NODE_PREDICATE_UNSUPPORTED"),
])
def test_only_two_constant_predicate_bodies_are_supported(predicate: bytes, reason: str):
    field = _read(_image(predicate=predicate))

    assert field["status"] == "unknown"
    assert field["reason"] == reason
    assert "value" not in field


def test_out_of_image_method_pointer_fails_closed():
    image = _image()
    image.put_u64(VTABLE + 0x40, 0x7000000000)

    field = _read(image)

    assert field["status"] == "unknown"
    assert field["reason"] == "NODE_PREDICATE_OUTSIDE_IMAGE"


def test_owner_vector_range_bound_is_enforced_before_entry_reads():
    image = _image(flags=4, owner_entries=[])
    image.put_u64(RECORD + 0x8A8, CONTAINER)
    image.put_u64(CONTAINER + 0x28, VECTOR)
    image.put_u64(CONTAINER + 0x30, VECTOR + 4097 * 8)

    field = _read(image)

    assert field["status"] == "unknown"
    assert field["reason"] == "OWNER_ENTRIES_RANGE_INVALID"
    assert not any("owner_entry_" in label for _, _, label in image.reads)


def test_required_read_failure_is_unknown_and_preserves_budget_trace():
    image = _image()
    image.fail_labels.add("province_trade_gates.node_predicate_code")

    field = _read(image)

    assert field["status"] == "unknown"
    assert field["reason"].startswith("READ_FAILED:")
    assert field["raw_inputs"]["read_budget"]["calls"] == len(field["raw_inputs"]["reads"])
    assert field["raw_inputs"]["read_budget"]["bytes_requested"] == sum(
        row["size"] for row in field["raw_inputs"]["reads"])


def test_before_after_gate_memory_comparison_retracts_drifting_predicate():
    image = _image()
    image.mutate_on["province_trade_gates.node_predicate_code"] = (
        2, METHOD, b"\xb0\x00\xc3")

    field = _read(image)

    assert field["status"] == "unknown"
    assert field["reason"] == "CALCULATION_GATES_CHANGED"
    assert field["raw_inputs"]["before"]["node_predicate_code"]["raw_hex"] == "b001c3"
    assert field["raw_inputs"]["after"]["node_predicate_code"]["raw_hex"] == "b000c3"
