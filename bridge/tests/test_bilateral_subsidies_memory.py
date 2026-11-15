from __future__ import annotations

import pytest

from bridge.information import bilateral_subsidies_memory as memory
from bridge.information.engine_dates import project_engine_date


BASE = 0x140000000
OBSERVER_SLOT = 19
TARGET_SLOT = 41
OBSERVER_POINTER = 0x50000000
TARGET_POINTER = 0x50001000
OBSERVER_ROWS = 0x60000000
TARGET_ROWS = 0x60010000
OBSERVER_ITEMS = 0x70000000
TARGET_ITEMS = 0x70020000
SUBSIDY = 0x80000000
OTHER_OBJECT = 0x90000000
START = 56_545_080
LITERAL_NATIVE_SUBSIDY_ROW_STRIDE = 0x48


def _fullref(tag: str, slot: int, generation: int) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryImage:
    """Sparse byte-addressed process-memory fixture with read fault hooks."""

    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.error_labels: set[str] = set()
        self.short_labels: set[str] = set()
        self.mutate_reads: dict[str, object] = {}

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + offset: value for offset, value in enumerate(raw)})

    def put_u32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label in self.error_labels:
            raise OSError("synthetic read failure")
        try:
            raw = bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("synthetic unmapped bytes") from exc
        if label in self.short_labels:
            return raw[:-1]
        callback = self.mutate_reads.get(label)
        if callback is not None:
            raw = callback(raw)  # type: ignore[operator]
        return raw


def _binding(tag: str, slot: int, pointer: int, generation: int) -> dict[str, object]:
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
                entries: list[tuple[int, int]], *, capacity: int | None = None,
                count: int | None = None) -> None:
    actual_capacity = len(entries) if capacity is None else capacity
    actual_count = len(entries) if count is None else count
    vector = owner + memory.OWNER_SUBSIDY_VECTOR_OFFSET
    data = data_pointer if actual_capacity else 0
    image.put_u64(vector + memory.VECTOR_DATA_OFFSET, data)
    image.put_i32(vector + memory.VECTOR_CAPACITY_OFFSET, actual_capacity)
    image.put_i32(vector + memory.VECTOR_COUNT_OFFSET, actual_count)
    if entries:
        raw = bytearray(len(entries) * memory.VECTOR_ITEM_STRIDE)
        for index, (slot, pointer) in enumerate(entries):
            offset = index * memory.VECTOR_ITEM_STRIDE
            raw[offset:offset + 4] = slot.to_bytes(4, "little", signed=True)
            raw[offset + 8:offset + 16] = pointer.to_bytes(8, "little", signed=False)
        image.put(data_pointer, bytes(raw))


def _put_row(image: MemoryImage, row_address: int, owner: int,
             self_ref: int, other_ref: int) -> None:
    image.put_u64(row_address, owner)
    image.put_u64(row_address + 8, self_ref)
    image.put_u64(row_address + 16, other_ref)


def _environment(*, payer: str = "FRA", amount: int = 12_500,
                 start: int = START, duration: int = 2,
                 forward_entries: list[tuple[int, int]] | None = None,
                 reverse_entries: list[tuple[int, int]] | None = None,
                 object_pointer: int = SUBSIDY) -> tuple[MemoryImage, dict, dict, dict]:
    image = MemoryImage()
    observer = _binding("FRA", OBSERVER_SLOT, OBSERVER_POINTER, 0x1234)
    target = _binding("ENG", TARGET_SLOT, TARGET_POINTER, 0x2345)
    observer_ref = int(str(observer["fullref"]), 0)
    target_ref = int(str(target["fullref"]), 0)
    image.put_u64(OBSERVER_POINTER + 0x20, observer_ref)
    image.put_u64(TARGET_POINTER + 0x20, target_ref)

    image.put_u64(OBSERVER_POINTER + memory.SUBSIDY_RELATION_ROWS_OFFSET, OBSERVER_ROWS)
    image.put_u64(TARGET_POINTER + memory.SUBSIDY_RELATION_ROWS_OFFSET, TARGET_ROWS)
    # Deliberately independent of the implementation constant: the captured
    # native layout uses 0x48-byte rows.
    observer_row = OBSERVER_ROWS + TARGET_SLOT * LITERAL_NATIVE_SUBSIDY_ROW_STRIDE
    target_row = TARGET_ROWS + OBSERVER_SLOT * LITERAL_NATIVE_SUBSIDY_ROW_STRIDE
    observer_owner = OBSERVER_POINTER + memory.SUBSIDY_ROW_OWNER_COUNTRY_OFFSET
    target_owner = TARGET_POINTER + memory.SUBSIDY_ROW_OWNER_COUNTRY_OFFSET
    _put_row(image, observer_row, observer_owner, observer_ref, target_ref)
    _put_row(image, target_row, target_owner, target_ref, observer_ref)

    if forward_entries is None:
        forward_entries = [(TARGET_SLOT, object_pointer)]
    if reverse_entries is None:
        reverse_entries = [(OBSERVER_SLOT, object_pointer)]
    _put_vector(image, observer_owner, OBSERVER_ITEMS, forward_entries)
    _put_vector(image, target_owner, TARGET_ITEMS, reverse_entries)

    payer_ref = observer_ref if payer == "FRA" else target_ref
    recipient_ref = target_ref if payer == "FRA" else observer_ref
    image.put(object_pointer, bytes(memory.SUBSIDY_OBJECT_SIZE))
    image.put_u64(object_pointer, BASE + memory.SUBSIDY_VTABLE_RVA)
    image.put_u32(object_pointer + 8, memory.SUBSIDY_MARKER)
    image.put_u32(object_pointer + 12, 0)
    image.put_u64(object_pointer + memory.SUBSIDY_PAYER_OFFSET, payer_ref)
    image.put_u64(object_pointer + memory.SUBSIDY_RECIPIENT_OFFSET, recipient_ref)
    image.put_i32(object_pointer + memory.SUBSIDY_START_DATE_OFFSET, start)
    image.put_u32(object_pointer + memory.SUBSIDY_FLAG_0X28_OFFSET, 0)
    image.put_i32(object_pointer + memory.SUBSIDY_MONTHLY_AMOUNT_OFFSET, amount)
    image.put_i32(object_pointer + memory.SUBSIDY_DURATION_YEARS_OFFSET, duration)
    return image, observer, target, {
        "observer_row": observer_row,
        "target_row": target_row,
        "observer_owner": observer_owner,
        "target_owner": target_owner,
        "observer_items": OBSERVER_ITEMS,
        "target_items": TARGET_ITEMS,
        "object": object_pointer,
    }


def _run(image: MemoryImage, observer: dict, target: dict) -> dict:
    return memory.read_state(image, BASE, observer, target)


@pytest.mark.parametrize(
    "payer,amount,start,duration,role",
    [("FRA", 12_500, START, 2, "payer"), ("ENG", -2_500, START - 24, -3, "recipient")],
)
def test_present_pair_decodes_both_directions_and_signed_nominal_terms(
        payer: str, amount: int, start: int, duration: int, role: str):
    image, observer, target, _ = _environment(
        payer=payer, amount=amount, start=start, duration=duration,
    )
    result = _run(image, observer, target)

    assert result["status"] == "known"
    assert result["partial"] is True and result["complete"] is False
    assert result["complete_country_contracts"] is False
    assert result["visibility_evaluated"] is False
    assert result["observed_pair"]["fullref_echo_verified"] is True
    contract = result["contract"]
    assert contract["status"] == "known" and contract["present"] is True
    assert contract["scope"] == "explicit_observer_target_pair_only"
    assert contract["payer"]["tag"] == payer
    assert contract["recipient"]["tag"] == ("ENG" if payer == "FRA" else "FRA")
    assert contract["observer_role"] == role
    assert contract["monthly_nominal_amount"] == {
        "raw": amount, "value": amount / 1000.0, "unit": "ducats",
        "scale": 1000, "period": "month",
        "basis": "native_subsidy_object_monthly_amount",
    }
    assert contract["start_date"]["raw"] == start
    assert contract["start_date"]["calendar"] == project_engine_date(start)
    assert contract["duration_years"]["raw"] == duration
    expected_end = ((start + duration * 0x2238 + 0x80000000) & 0xFFFFFFFF) - 0x80000000
    assert contract["displayed_end_date"]["raw"] == expected_end
    assert contract["displayed_end_date"]["calendar"] == project_engine_date(expected_end)
    assert contract["displayed_end_date"]["derivation"]["static_evidence_id"] == (
        "ev_e0253c163eeb06480ec3c8f15e82a5a8530c3ca7676d03f6fc30a0bbc84ef581"
    )
    assert contract["active_payment_obligation"]["status"] == "unknown"
    assert contract["relation_flag_0x28"]["status"] == "unknown"
    assert contract["term_legality"]["status"] == "unknown"


def test_both_empty_vectors_are_known_absence_for_only_this_pair():
    image, observer, target, _ = _environment(forward_entries=[], reverse_entries=[])
    result = _run(image, observer, target)

    assert result["status"] == "known"
    assert result["contract"]["status"] == "absent"
    assert result["contract"]["scope"] == "explicit_observer_target_pair_only"
    assert result["complete_country_contracts"] is False
    assert result["visibility_evaluated"] is False
    assert result["observed_pair"]["fullref_echo_verified"] is True


def test_literal_native_row_stride_places_both_pair_rows_at_0x48_offsets():
    image, observer, target, addresses = _environment()
    result = _run(image, observer, target)

    assert result["status"] == "known"
    assert addresses["observer_row"] == OBSERVER_ROWS + TARGET_SLOT * 0x48
    assert addresses["target_row"] == TARGET_ROWS + OBSERVER_SLOT * 0x48
    row_reads = [(address, label) for address, _size, label in image.reads
                 if label in {"pair.observer_to_target.row", "pair.target_to_observer.row"}]
    assert row_reads == [
        (OBSERVER_ROWS + TARGET_SLOT * 0x48, "pair.observer_to_target.row"),
        (TARGET_ROWS + OBSERVER_SLOT * 0x48, "pair.target_to_observer.row"),
    ]


def test_literal_native_start_sentinel_is_unknown_and_old_value_is_not_sentinel():
    image, observer, target, addresses = _environment(start=0)
    # Native ctor stores DWORD 0x029c77f8 (little-endian f8 77 9c 02).
    image.put(addresses["object"] + 0x20, bytes.fromhex("f8779c02"))
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "SUBSIDY_START_DATE_SENTINEL"
    assert result["contract"]["status"] == "unknown"

    image, observer, target, addresses = _environment(start=0)
    # The previously truncated value is valid data, not the native sentinel.
    image.put(addresses["object"] + 0x20, (0x0029C77F).to_bytes(4, "little"))
    result = _run(image, observer, target)
    assert result["status"] == "known"
    assert result["contract"]["present"] is True
    assert result["contract"]["start_date"]["raw"] == 0x0029C77F


def test_signed32_displayed_end_date_wraps_like_native_i32():
    image, observer, target, _ = _environment(start=2_147_483_600, duration=2)
    result = _run(image, observer, target)

    assert result["status"] == "known"
    end = result["contract"]["displayed_end_date"]
    assert end["raw"] == -2_147_466_176
    assert end["raw_hex"] == "40440080"
    assert end["derivation"]["intermediate_and_final_wrap"] == (
        "low_32_bits_interpreted_as_signed_i32"
    )


@pytest.mark.parametrize(
    "forward,reverse,reason",
    [
        ([(TARGET_SLOT, SUBSIDY)], [], "ASYMMETRIC_PAIR_SUBSIDY"),
        ([(TARGET_SLOT, SUBSIDY)], [(OBSERVER_SLOT, OTHER_OBJECT)],
         "BILATERAL_SUBSIDY_POINTER_MISMATCH"),
    ],
)
def test_one_sided_or_conflicting_pair_pointers_are_unknown(forward, reverse, reason):
    image, observer, target, _ = _environment(
        forward_entries=forward, reverse_entries=reverse,
    )
    result = _run(image, observer, target)

    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert not any(label == "contract.relation_object" for _, _, label in image.reads)


@pytest.mark.parametrize(
    "which,reason",
    [("observer", "OBSERVER_AFTER_FULLREF_ECHO_MISMATCH"),
     ("target", "TARGET_AFTER_FULLREF_ECHO_MISMATCH")],
)
def test_live_country_fullref_change_after_scan_withdraws_result(which, reason):
    image, observer, target, _ = _environment(forward_entries=[], reverse_entries=[])
    label = f"binding.{which}_after.fullref_echo"
    image.mutate_reads[label] = lambda raw: bytes([raw[0] ^ 1]) + raw[1:]

    result = _run(image, observer, target)

    assert result["status"] == "unknown"
    assert result["reason"] == reason


@pytest.mark.parametrize("mutated_offset", [0, 8, 16])
def test_pair_row_owner_or_fullref_change_after_scan_withdraws_result(mutated_offset: int):
    image, observer, target, _ = _environment(forward_entries=[], reverse_entries=[])
    label = "pair.observer_to_target.row_after"

    def mutate(raw: bytes) -> bytes:
        changed = bytearray(raw)
        changed[mutated_offset] ^= 1
        return bytes(changed)

    image.mutate_reads[label] = mutate
    result = _run(image, observer, target)

    assert result["status"] == "unknown"
    assert result["reason"] == "OBSERVER_TO_TARGET_ROW_CHANGED_AFTER_VECTOR_READ"


def test_initial_row_must_belong_to_country_owner_and_echo_both_refs():
    image, observer, target, addresses = _environment()
    image.put_u64(addresses["observer_row"], addresses["observer_owner"] + 8)
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "OBSERVER_TO_TARGET_ROW_OWNER_MISMATCH"
    assert not any("vector_header" in label for _, _, label in image.reads)

    image, observer, target, addresses = _environment()
    image.put_u64(addresses["observer_row"] + 16, 0x12345678)
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "OBSERVER_TO_TARGET_ROW_FULLREF_MISMATCH"
    assert not any("vector_header" in label for _, _, label in image.reads)


def test_duplicate_slots_are_unknown_even_when_the_target_pointer_agrees():
    image, observer, target, _ = _environment(
        forward_entries=[(TARGET_SLOT, SUBSIDY), (TARGET_SLOT, SUBSIDY)],
    )
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "OBSERVER_TO_TARGET_VECTOR_DUPLICATE_SLOT"


@pytest.mark.parametrize(
    "capacity,count,reason",
    [(1, 2, "OBSERVER_TO_TARGET_VECTOR_BOUNDS_INVALID"),
     (4097, 0, "OBSERVER_TO_TARGET_VECTOR_BOUNDS_INVALID"),
     (-1, 0, "OBSERVER_TO_TARGET_VECTOR_BOUNDS_INVALID")],
)
def test_vector_capacity_and_count_bounds_are_checked(capacity, count, reason):
    image, observer, target, addresses = _environment(forward_entries=[], reverse_entries=[])
    vector = addresses["observer_owner"] + memory.OWNER_SUBSIDY_VECTOR_OFFSET
    image.put_u64(vector + memory.VECTOR_DATA_OFFSET, OBSERVER_ITEMS)
    image.put_i32(vector + memory.VECTOR_CAPACITY_OFFSET, capacity)
    image.put_i32(vector + memory.VECTOR_COUNT_OFFSET, count)

    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == reason


def test_shortread_or_read_exception_returns_unknown():
    image, observer, target, _ = _environment()
    image.short_labels.add("pair.observer_to_target.vector_header")
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "READ_FAILED:pair.observer_to_target.vector_header"

    image, observer, target, _ = _environment()
    image.error_labels.add("pair.target_to_observer.items[0:1]")
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "READ_FAILED:pair.target_to_observer.items[0:1]"


def test_read_budget_exhaustion_never_returns_a_partial_contract(monkeypatch):
    image, observer, target, _ = _environment()
    monkeypatch.setattr(memory, "MAX_READ_CALLS", 6)
    result = _run(image, observer, target)

    assert result["status"] == "unknown"
    assert result["reason"] == "READ_BUDGET_EXCEEDED"
    assert result["contract"]["status"] == "unknown"
    assert result["raw_inputs"]["read_budget"]["calls"] == 6
    assert result["raw_inputs"]["read_budget"]["bytes_requested"] <= memory.MAX_TOTAL_READ_BYTES
    assert any(row.get("reason") == "READ_BUDGET_EXCEEDED"
               for row in result["raw_inputs"]["ordered_read_trace"])


def test_maximum_vectors_are_chunked_within_budgets():
    forward = [(slot, SUBSIDY if slot == TARGET_SLOT else OTHER_OBJECT + slot * 8)
               for slot in range(memory.MAX_VECTOR_ITEMS)]
    reverse = [(slot, SUBSIDY if slot == OBSERVER_SLOT else OTHER_OBJECT + 0x10000 + slot * 8)
               for slot in range(memory.MAX_VECTOR_ITEMS)]
    image, observer, target, addresses = _environment(
        forward_entries=forward, reverse_entries=reverse,
    )
    _put_vector(image, addresses["observer_owner"], OBSERVER_ITEMS, forward,
                capacity=memory.MAX_VECTOR_ITEMS)
    _put_vector(image, addresses["target_owner"], TARGET_ITEMS, reverse,
                capacity=memory.MAX_VECTOR_ITEMS)

    result = _run(image, observer, target)

    assert result["status"] == "known"
    budget = result["raw_inputs"]["read_budget"]
    assert budget["calls"] <= memory.MAX_READ_CALLS
    assert budget["bytes_requested"] <= memory.MAX_TOTAL_READ_BYTES
    assert max(size for _, size, _ in image.reads) <= memory.MAX_SINGLE_READ_BYTES
    assert sum(size for _, size, _ in image.reads) == budget["bytes_requested"]

