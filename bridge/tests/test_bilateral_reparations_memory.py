"""Offline fake-memory tests for the bilateral reparations reader."""
from __future__ import annotations

import pytest

from bridge.information import bilateral_reparations_memory as memory
from bridge.information.engine_dates import project_engine_date


BASE = 0x140000000
OBSERVER_SLOT = 19
TARGET_SLOT = 41
OBSERVER_POINTER = 0x50000000
TARGET_POINTER = 0x50001000
OBSERVER_ROWS = 0x60000000
TARGET_ROWS = 0x60010000
OBSERVER_OWNER = 0x70000000
TARGET_OWNER = 0x70001000
OBSERVER_ITEMS = 0x80000000
TARGET_ITEMS = 0x80020000
TREATY = 0x90000000
OTHER_POINTERS = 0xA0000000
START_DATE = 56_545_080
END_DATE = 56_632_680


def _fullref(tag: str, slot: int, generation: int = 0x1234) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryImage:
    """A byte-addressed fake process image; it contains no reader stubs."""

    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.error_at: set[int] = set()
        self.short_at: set[int] = set()

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + offset: byte for offset, byte in enumerate(raw)})

    def put_u32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if address in self.error_at:
            raise OSError("synthetic read failure")
        try:
            raw = bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("synthetic unmapped bytes") from exc
        return raw[:-1] if address in self.short_at else raw


def _binding(tag: str, slot: int, pointer: int, generation: int) -> dict:
    fullref = _fullref(tag, slot, generation)
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "country_fullref_address": hex(pointer + 0x20),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "table_entry_address": hex(0x61000000 + slot * 8),
        "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
    }


def _put_vector(image: MemoryImage, owner: int, data_pointer: int,
                entries: list[tuple[int, int]], *, capacity: int | None = None) -> None:
    vector = owner + memory.OWNER_PAIR_VECTOR_OFFSET
    count = len(entries)
    actual_capacity = count if capacity is None else capacity
    image.put_u64(owner + 0x98, data_pointer if actual_capacity else 0)
    image.put_i32(owner + 0xA0, actual_capacity)
    image.put_i32(owner + 0xA4, count)
    if count:
        raw = bytearray(count * memory.VECTOR_ITEM_STRIDE)
        for index, (slot, pointer) in enumerate(entries):
            offset = index * memory.VECTOR_ITEM_STRIDE
            raw[offset:offset + 4] = slot.to_bytes(4, "little", signed=True)
            raw[offset + 8:offset + 16] = pointer.to_bytes(8, "little", signed=False)
        image.put(data_pointer, bytes(raw))
    assert vector == owner + 0x90


def _put_relation(image: MemoryImage, observer: dict, target: dict, *,
                  payer: str = "FRA", claimant: str = "ENG",
                  start: int = START_DATE, end: int = END_DATE,
                  pointer: int = TREATY) -> None:
    payer_ref = int(observer["fullref"], 0) if payer == "FRA" else int(target["fullref"], 0)
    claimant_ref = int(observer["fullref"], 0) if claimant == "FRA" else int(target["fullref"], 0)
    image.put_u64(pointer, BASE + memory.RELATION_TABLE_RVA)
    image.put_u32(pointer + 8, memory.RELATION_MARKER)
    image.put_u32(pointer + 12, 0)
    image.put_u64(pointer + memory.RELATION_PAYER_OFFSET, payer_ref)
    image.put_u64(pointer + memory.RELATION_CLAIMANT_OFFSET, claimant_ref)
    image.put_i32(pointer + memory.RELATION_START_DATE_OFFSET, start)
    image.put_i32(pointer + memory.RELATION_END_DATE_OFFSET, end)


def _environment(*, present: bool = True, payer: str = "FRA",
                  entries: list[tuple[int, int]] | None = None,
                  reverse_entries: list[tuple[int, int]] | None = None,
                  target_slot: int = TARGET_SLOT) -> tuple[MemoryImage, dict, dict, dict]:
    image = MemoryImage()
    observer = _binding("FRA", OBSERVER_SLOT, OBSERVER_POINTER, 0x1234)
    target = _binding("ENG", target_slot, TARGET_POINTER, 0x2345)
    image.put_u64(OBSERVER_POINTER + 0x20, int(observer["fullref"], 0))
    image.put_u64(TARGET_POINTER + 0x20, int(target["fullref"], 0))

    image.put_u64(OBSERVER_POINTER + memory.COUNTRY_RELATION_ROWS_OFFSET, OBSERVER_ROWS)
    image.put_u64(TARGET_POINTER + memory.COUNTRY_RELATION_ROWS_OFFSET, TARGET_ROWS)
    observer_row = OBSERVER_ROWS + target_slot * memory.PAIR_ROW_STRIDE
    target_row = TARGET_ROWS + OBSERVER_SLOT * memory.PAIR_ROW_STRIDE
    image.put_u64(observer_row + memory.PAIR_OWNER_OFFSET, OBSERVER_OWNER)
    image.put_u64(observer_row + memory.PAIR_SELF_FULLREF_OFFSET, int(observer["fullref"], 0))
    image.put_u64(observer_row + memory.PAIR_OTHER_FULLREF_OFFSET, int(target["fullref"], 0))
    image.put_u64(target_row + memory.PAIR_OWNER_OFFSET, TARGET_OWNER)
    image.put_u64(target_row + memory.PAIR_SELF_FULLREF_OFFSET, int(target["fullref"], 0))
    image.put_u64(target_row + memory.PAIR_OTHER_FULLREF_OFFSET, int(observer["fullref"], 0))

    if entries is None:
        entries = [(target_slot, TREATY)] if present else []
    if reverse_entries is None:
        reverse_entries = [(OBSERVER_SLOT, TREATY)] if present else []
    _put_vector(image, OBSERVER_OWNER, OBSERVER_ITEMS, entries)
    _put_vector(image, TARGET_OWNER, TARGET_ITEMS, reverse_entries)
    if present:
        claimant = "ENG" if payer == "FRA" else "FRA"
        _put_relation(image, observer, target, payer=payer, claimant=claimant)
    return image, observer, target, {
        "observer_row": observer_row,
        "target_row": target_row,
        "observer_owner": OBSERVER_OWNER,
        "target_owner": TARGET_OWNER,
        "observer_items": OBSERVER_ITEMS,
        "target_items": TARGET_ITEMS,
        "treaty": TREATY,
    }


def _run(image: MemoryImage, observer: dict, target: dict, *, date: int = START_DATE,
         base: int = BASE) -> dict:
    return memory.read_state(image, base, observer, target, date)


@pytest.mark.parametrize("payer,claimant", [("FRA", "ENG"), ("ENG", "FRA")])
@pytest.mark.parametrize("date,contains", [
    (START_DATE - 1, False),
    (START_DATE, True),
    (END_DATE - 1, True),
    (END_DATE, False),
])
def test_reads_both_contract_directions_and_half_open_date_window(
        payer: str, claimant: str, date: int, contains: bool):
    image, observer, target, _addresses = _environment(payer=payer)
    result = _run(image, observer, target, date=date)

    assert result["status"] == "known"
    assert result["partial"] is True and result["complete"] is False
    assert result["complete_country_contracts"] is False
    assert result["observed_pair"]["fullref_echo_verified"] is True
    contract = result["contract"]
    assert contract["status"] == "known" and contract["present"] is True
    assert contract["payer"]["tag"] == payer
    assert contract["claimant"]["tag"] == claimant
    assert contract["start_date"]["raw"] == START_DATE
    assert contract["start_date"]["calendar"] == project_engine_date(START_DATE)
    assert contract["end_date"]["raw"] == END_DATE
    assert contract["end_date"]["calendar"] == project_engine_date(END_DATE)
    assert contract["date_window_contains_observed_date"] is contains
    assert contract["active_payment_obligation"]["status"] == "unknown"
    assert contract["payment_amount"]["status"] == "unknown"
    assert contract["relation_flag_0x28"]["status"] == "unknown"
    assert result["raw_inputs"]["visibility_evaluated"] is False


def test_both_empty_vectors_are_known_absence_for_only_the_observed_pair():
    image, observer, target, _addresses = _environment(present=False)
    result = _run(image, observer, target)

    assert result["status"] == "known"
    assert result["contract"]["status"] == "absent"
    assert result["contract"]["present"] is False
    assert result["contract"]["scope"] == "explicit_observer_target_pair_only"
    assert result["complete_country_contracts"] is False
    assert result["contract"]["payment_amount"]["status"] == "unknown"


def test_one_sided_pointer_or_different_bidirectional_pointer_is_unknown():
    image, observer, target, addresses = _environment()
    image.put_u64(addresses["target_items"] + 8, TREATY + 0x1000)
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["contract"]["status"] == "unknown"
    assert result["reason"] == "BILATERAL_RELATION_POINTER_MISMATCH"
    assert not any("present" in key for key in result["contract"])

    image, observer, target, addresses = _environment()
    image.put_i32(addresses["target_owner"] + 0xA4, 0)
    image.put_i32(addresses["target_owner"] + 0xA0, 0)
    image.put_u64(addresses["target_owner"] + 0x98, 0)
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "ASYMMETRIC_PAIR_RELATION"


@pytest.mark.parametrize("which", ["observer", "target"])
def test_pair_row_fullrefs_must_echo_exact_bound_references(which: str):
    image, observer, target, addresses = _environment()
    row = addresses[f"{which}_row"]
    expected = observer if which == "observer" else target
    image.put_u64(row + memory.PAIR_SELF_FULLREF_OFFSET,
                  int(expected["fullref"], 0) ^ (1 << 48))
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["contract"]["status"] == "unknown"
    assert result["reason"].endswith("ROW_FULLREF_MISMATCH")
    assert "start_date" not in result["contract"]


def test_duplicate_slot_in_either_vector_withdraws_the_whole_pair():
    image, observer, target, _addresses = _environment(
        entries=[(TARGET_SLOT, TREATY), (TARGET_SLOT, TREATY)],
        reverse_entries=[(OBSERVER_SLOT, TREATY)],
    )
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "OBSERVER_TO_TARGET_VECTOR_DUPLICATE_SLOT"
    assert result["contract"] == {"status": "unknown", "reason": result["reason"]}


@pytest.mark.parametrize("field,value,reason", [
    ("capacity", -1, "OBSERVER_TO_TARGET_VECTOR_BOUNDS_INVALID"),
    ("capacity", 4097, "OBSERVER_TO_TARGET_VECTOR_BOUNDS_INVALID"),
    ("count", -1, "OBSERVER_TO_TARGET_VECTOR_BOUNDS_INVALID"),
])
def test_invalid_vector_capacity_or_count_is_unknown(field: str, value: int, reason: str):
    image, observer, target, addresses = _environment()
    offset = 0xA0 if field == "capacity" else 0xA4
    image.put_i32(addresses["observer_owner"] + offset, value)
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert result["contract"]["status"] == "unknown"


def test_bad_relation_vtable_marker_parties_or_date_window_is_unknown():
    mutations = [
        (TREATY, 0x1400000000000000),
        (TREATY + 8, 0x166),
        (TREATY + memory.RELATION_PAYER_OFFSET, _fullref("BUR", 22)),
        (TREATY + memory.RELATION_END_DATE_OFFSET, START_DATE),
    ]
    for address, value in mutations:
        image, observer, target, _addresses = _environment()
        if address == TREATY + 8:
            image.put_u32(address, value)
        elif address in (TREATY, TREATY + memory.RELATION_PAYER_OFFSET):
            image.put_u64(address, value)
        else:
            image.put_i32(address, value)
        result = _run(image, observer, target)
        assert result["status"] == "unknown"
        assert result["contract"]["status"] == "unknown"
        assert "present" not in result["contract"]


def test_shortread_and_read_exception_return_unknown_without_partial_contract():
    image, observer, target, addresses = _environment()
    image.short_at.add(addresses["observer_row"])
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"].startswith("READ_FAILED:")
    assert result["contract"]["status"] == "unknown"

    image, observer, target, addresses = _environment()
    image.error_at.add(addresses["target_row"])
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"].startswith("READ_FAILED:")
    assert result["contract"]["status"] == "unknown"


def test_invalid_base_and_boolean_date_are_rejected_before_memory_reads():
    image, observer, target, _addresses = _environment()
    result = _run(image, observer, target, base=True)
    assert result["status"] == "unknown"
    assert result["reason"] == "MODULE_BASE_POINTER_INVALID"
    assert image.reads == []

    result = _run(image, observer, target, date=True)
    assert result["status"] == "unknown"
    assert result["reason"] == "DATE_RAW_INVALID"
    assert image.reads == []


def test_only_fra_pair_is_accepted():
    image, _observer, target, _addresses = _environment()
    bur = _binding("BUR", OBSERVER_SLOT, OBSERVER_POINTER, 0x1234)
    image.put_u64(OBSERVER_POINTER + 0x20, int(bur["fullref"], 0))
    result = _run(image, bur, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "OBSERVER_MUST_BE_FRA"
    assert image.reads == []


@pytest.mark.parametrize("role,pointer", [
    ("observer_after", OBSERVER_POINTER),
    ("target_after", TARGET_POINTER),
])
def test_identity_change_after_the_contract_read_withdraws_contract(role, pointer):
    image, observer, target, _addresses = _environment()

    def changing_reader(address, size, label):
        if label == f"binding.{role}.fullref_echo":
            # The slot/tag remain unchanged; only the reference generation
            # changes after the relation object was copied.
            image.data[pointer + 0x20 + 6] ^= 1
        return image.read(address, size, label)

    result = memory.read_state(changing_reader, BASE, observer, target, START_DATE)
    assert any(label == "contract.relation_object" for _, _, label in image.reads)
    assert result["status"] == "unknown"
    assert result["reason"] == role.upper() + "_FULLREF_ECHO_MISMATCH"
    assert result["contract"] == {"status": "unknown", "reason": result["reason"]}


def test_maximum_vectors_are_chunked_and_stay_within_real_budgets():
    full_entries_observer = [
        (slot, TREATY if slot == TARGET_SLOT else OTHER_POINTERS + slot * 0x10)
        for slot in range(memory.MAX_VECTOR_ITEMS)
    ]
    full_entries_target = [
        (slot, TREATY if slot == OBSERVER_SLOT else OTHER_POINTERS + 0x10000 + slot * 0x10)
        for slot in range(memory.MAX_VECTOR_ITEMS)
    ]
    image, observer, target, _addresses = _environment(
        entries=full_entries_observer, reverse_entries=full_entries_target,
    )
    result = _run(image, observer, target)

    assert result["status"] == "known"
    budget = result["raw_inputs"]["read_budget"]
    assert budget["bytes_requested"] <= memory.MAX_TOTAL_READ_BYTES
    assert budget["calls"] <= memory.MAX_READ_CALLS
    assert all(size <= memory.MAX_SINGLE_READ_BYTES for _address, size, _label in image.reads)
    assert all(item["pointer_checked"] is True
               for item in result["raw_inputs"]["ordered_read_trace"])


def test_read_budget_exhaustion_does_not_return_half_contract(monkeypatch):
    entries = [
        (slot, TREATY if slot == TARGET_SLOT else OTHER_POINTERS + slot * 0x10)
        for slot in range(memory.MAX_VECTOR_ITEMS)
    ]
    reverse = [
        (slot, TREATY if slot == OBSERVER_SLOT else OTHER_POINTERS + 0x10000 + slot * 0x10)
        for slot in range(memory.MAX_VECTOR_ITEMS)
    ]
    image, observer, target, _addresses = _environment(
        entries=entries, reverse_entries=reverse,
    )
    monkeypatch.setattr(memory, "MAX_TOTAL_READ_BYTES", 8192)
    result = _run(image, observer, target)

    assert result["status"] == "unknown"
    assert result["reason"] == "READ_BUDGET_EXCEEDED"
    assert result["contract"] == {"status": "unknown", "reason": "READ_BUDGET_EXCEEDED"}
    assert result["raw_inputs"]["read_budget"]["bytes_requested"] <= 8192
    assert result["raw_inputs"]["ordered_read_trace"][-1]["status"] == "rejected"

