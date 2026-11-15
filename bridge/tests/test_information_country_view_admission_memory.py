"""Offline fake-memory tests for the bounded country-view admission leaf."""
from __future__ import annotations

import pytest

from bridge.information import country_view_admission_memory as memory


MODULE_BASE = 0x140000000
DATABASE = 0x6200000000
COUNTRY_TABLE = 0x6300000000
COUNTRY_BASE = 0x6400000000
RELATION_TABLE = 0x6500000000
RELATION_OWNER = 0x6600000000
COUNTERS = 0x6700000000
CAPITAL = 0x6800000000
OBSERVER_BITSET = 0x6900000000


def _fullref(tag: str, slot: int, generation: int = 0x1234) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryImage:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.short_at: set[int] = set()
        self.error_at: set[int] = set()

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + offset: byte for offset, byte in enumerate(raw)})

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def put_u32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if address in self.error_at:
            raise OSError("synthetic RPM failure")
        result = bytes(self.data[address + offset] for offset in range(size))
        return result[:-1] if address in self.short_at else result


def _make_bindings(observer_slot: int = 189, target_slot: int = 300,
                   observer_tag: str = "FRA", target_tag: str = "POR",
                   observer_generation: int = 0x1234,
                   target_generation: int = 0x1234,
                   *, observer_pointer: int | None = None,
                   target_pointer: int | None = None) -> tuple[dict, dict[str, int]]:
    count = max(observer_slot, target_slot) + 1
    observer_pointer = (COUNTRY_BASE + observer_slot * 0x1000
                        if observer_pointer is None else observer_pointer)
    target_pointer = (COUNTRY_BASE + target_slot * 0x1000
                      if target_pointer is None else target_pointer)
    observer_ref = _fullref(observer_tag, observer_slot, observer_generation)
    target_ref = _fullref(target_tag, target_slot, target_generation)

    rows: list[dict] = []
    for slot in range(count):
        rows.append({
            "slot": slot,
            "table_entry_address": hex(COUNTRY_TABLE + slot * 8),
            "table_entry_raw_hex": (b"\x00" * 8).hex(),
            "country_pointer": None,
            "fullref_address": None,
            "fullref": None,
            "fullref_raw_hex": None,
            "tag": None,
            "fullref_slot": None,
        })
    requested: dict[str, dict] = {}
    for tag, slot, pointer, fullref in (
        (observer_tag, observer_slot, observer_pointer, observer_ref),
        (target_tag, target_slot, target_pointer, target_ref),
    ):
        row = {
            "slot": slot,
            "table_entry_address": hex(COUNTRY_TABLE + slot * 8),
            "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
            "country_pointer": hex(pointer),
            "fullref_address": hex(pointer + memory.COUNTRY_FULLREF_OFFSET),
            "fullref": hex(fullref),
            "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
            "tag": tag,
            "fullref_slot": slot,
        }
        rows[slot] = row
        requested[tag] = {
            "tag": tag,
            "slot": slot,
            "country_pointer": hex(pointer),
            "country_fullref_address": hex(pointer + memory.COUNTRY_FULLREF_OFFSET),
            "fullref": hex(fullref),
            "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
            "table_entry_address": hex(COUNTRY_TABLE + slot * 8),
            "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
        }
    return ({
        "status": "observed",
        "basis": "country_manager_table_tag_slot_binding",
        "module_base": hex(MODULE_BASE),
        "database": hex(DATABASE),
        "table": hex(COUNTRY_TABLE),
        "count": count,
        "rows": rows,
        "requested": requested,
    }, {
        "observer_slot": observer_slot,
        "target_slot": target_slot,
        "observer_pointer": observer_pointer,
        "target_pointer": target_pointer,
        "observer_fullref": observer_ref,
        "target_fullref": target_ref,
    })


def _make_image(observer_slot: int = 189, target_slot: int = 300,
                observer_tag: str = "FRA", target_tag: str = "POR",
                observer_generation: int = 0x1234, target_generation: int = 0x1234,
                counter: int = 0, capital_flags: int = 0,
                observer_bit: int = 0, *,
                observer_pointer: int | None = None,
                target_pointer: int | None = None,
                relation_table: int = RELATION_TABLE,
                owner: int = RELATION_OWNER,
                counters: int = COUNTERS,
                capital: int = CAPITAL,
                bitset: int = OBSERVER_BITSET) -> tuple[MemoryImage, dict, dict[str, int]]:
    bindings, refs = _make_bindings(
        observer_slot, target_slot, observer_tag, target_tag,
        observer_generation, target_generation,
        observer_pointer=observer_pointer, target_pointer=target_pointer,
    )
    image = MemoryImage()
    for index, (_, rva) in enumerate(memory.SPECIAL_TARGET_SLOT_RVAS):
        image.put_i32(MODULE_BASE + rva, -index - 10)

    image.put_u64(refs["observer_pointer"] + memory.RELATION_TABLE_OFFSET, relation_table)
    row = relation_table + target_slot * memory.RELATION_ROW_STRIDE
    image.put_u64(row + memory.RELATION_ROW_OWNER_OFFSET, owner)
    image.put_u64(row + memory.RELATION_ROW_RECIPIENT_FULLREF_OFFSET,
                  refs["target_fullref"])
    image.put_u64(owner + memory.RELATION_OWNER_COUNTERS_OFFSET, counters)
    counter_address = (counters + memory.RELATION_COUNTER_FIRST_OFFSET
                      + target_slot * memory.RELATION_COUNTER_STRIDE)
    image.put_i32(counter_address, counter)

    image.put_u64(refs["target_pointer"] + memory.COUNTRY_CAPITAL_OFFSET, capital)
    image.put(capital + memory.CAPITAL_VIEW_FLAGS_OFFSET, bytes([capital_flags & 0xFF]))
    image.put_u64(capital + memory.CAPITAL_OBSERVER_BITSET_OFFSET, bitset)
    word_address = bitset + (observer_slot >> 5) * memory.CAPITAL_OBSERVER_BITSET_WORD_STRIDE
    word = (observer_bit & 1) << (observer_slot & 0x1F)
    image.put_u32(word_address, word)
    return image, bindings, refs


def _run(image: MemoryImage, bindings: dict, observer: str = "FRA",
         target: str = "POR") -> dict:
    return memory.read_country_view_admission(image.read, MODULE_BASE, bindings,
                                              observer, target)


def test_relation_counter_positive_admits_and_does_not_read_capital():
    image, bindings, refs = _make_image(counter=1)

    result = _run(image, bindings)

    assert result["status"] == "known"
    assert result["admitted"] is True
    assert result["basis"] == "native_country_view_predicate_projected_to_observer"
    assert result["admission_scope"] == "mil_value_native_country_selection_predicate_only"
    assert result["observer"]["tag"] == "FRA"
    assert result["target"]["tag"] == "POR"
    assert result["observer"]["binding"]["country_pointer_hex"] == hex(refs["observer_pointer"])
    assert result["target"]["binding"]["country_pointer_hex"] == hex(refs["target_pointer"])
    assert result["actual_UI_observed"] is False
    assert result["current_client_predicate_executed"] is False
    assert result["physical_global_observer_checked"] is False
    labels = [label for _, _, label in image.reads]
    assert "observer.relation_table_pointer" in labels
    assert not any(label.startswith("target_country.capital") for label in labels)
    assert result["budget"]["bytes_requested"] == sum(size for _, size, _ in image.reads)
    assert result["budget"]["bytes_requested"] <= 4096
    assert max(size for _, size, _ in image.reads) <= 8


def test_counter_below_one_with_capital_view_bit_clear_admits_without_bitset_read():
    image, bindings, _ = _make_image(counter=0, capital_flags=0)

    result = _run(image, bindings)

    assert result["status"] == "known"
    assert result["admitted"] is True
    assert result["target"]["relation_counter_signed_i32"] == 0
    assert result["target"]["capital_view_flags_u8"] == 0
    assert not any("observer_bitset" in label for _, _, label in image.reads)


@pytest.mark.parametrize("observer_slot", [31, 32, 63])
@pytest.mark.parametrize("observer_bit,expected", [(0, False), (1, True)])
def test_capital_flag_fallback_uses_observer_bit_across_word_boundaries(
        observer_slot: int, observer_bit: int, expected: bool):
    image, bindings, _ = _make_image(observer_slot=observer_slot, target_slot=300,
                                      counter=-1, capital_flags=0x10,
                                      observer_bit=observer_bit)

    result = _run(image, bindings)

    assert result["status"] == "known"
    assert result["admitted"] is expected
    assert result["observer"]["bitset_word_index"] == observer_slot >> 5
    assert result["observer"]["bitset_bit_index"] == observer_slot & 0x1F
    assert result["observer"]["bit_value"] == observer_bit
    expected_word_address = OBSERVER_BITSET + (observer_slot >> 5) * 4
    assert result["observer"]["bitset_word_address"] == hex(expected_word_address)


@pytest.mark.parametrize("special_index", [0, 1, 2])
def test_each_native_special_target_slot_rejects_and_short_circuits(
        special_index: int):
    target_slot = 300
    image, bindings, _ = _make_image(target_slot=target_slot, counter=1)
    for index, (_, rva) in enumerate(memory.SPECIAL_TARGET_SLOT_RVAS):
        value = target_slot if index == special_index else -index - 10
        image.put_i32(MODULE_BASE + rva, value)

    result = _run(image, bindings)

    assert result["status"] == "known"
    assert result["admitted"] is False
    assert result["refs"]["target_special_slot_signed_i32"] == target_slot
    assert len(image.reads) == special_index + 1
    assert all("relation" not in label for _, _, label in image.reads)


@pytest.mark.parametrize(
    "generation,expected_path",
    [(0x0000, "target_high_byte_zero_rejected"),
     (0x0107, "target_byte48_seven_rejected")],
)
def test_target_ref_native_flag_gates_reject_without_rpm(generation: int,
                                                          expected_path: str):
    image, bindings, _ = _make_image(target_generation=generation, counter=1)

    result = _run(image, bindings)

    assert result["status"] == "known"
    assert result["admitted"] is False
    assert result["predicate_path"][-1] == expected_path
    assert image.reads == []


@pytest.mark.parametrize("generation", [0x0000, 0x0107])
def test_invalid_observer_ref_is_unknown_not_native_bypass(generation: int):
    image, bindings, _ = _make_image(observer_generation=generation, counter=0,
                                     capital_flags=0x10, observer_bit=0)

    result = _run(image, bindings)

    assert result["status"] == "unknown"
    assert result["admitted"] is None
    assert result["reason"] == "observer_fullref_not_ordinary"
    assert image.reads == []


def test_row_requires_exact_target_fullref_including_generation():
    image, bindings, refs = _make_image(counter=1)
    row = RELATION_TABLE + refs["target_slot"] * memory.RELATION_ROW_STRIDE
    image.put_u64(row + memory.RELATION_ROW_RECIPIENT_FULLREF_OFFSET,
                  refs["target_fullref"] ^ (1 << 48))

    result = _run(image, bindings)

    assert result["status"] == "unknown"
    assert result["admitted"] is None
    assert result["reason"] == "relation_row_recipient_fullref_mismatch"
    assert result["raw_operands"][-1]["native_operand"] == "relation_row.recipient_fullref"


def test_direction_uses_observer_fra_relation_table_and_target_por_capital():
    image, bindings, refs = _make_image(counter=0, capital_flags=0)

    result = _run(image, bindings, observer="FRA", target="POR")

    labels = [(address, label) for address, _, label in image.reads]
    assert result["observer"]["tag"] == "FRA"
    assert result["target"]["tag"] == "POR"
    assert (refs["observer_pointer"] + memory.RELATION_TABLE_OFFSET,
            "observer.relation_table_pointer") in labels
    assert (refs["target_pointer"] + memory.COUNTRY_CAPITAL_OFFSET,
            "target_country.capital_pointer") in labels
    assert not any(address == refs["target_pointer"] + memory.RELATION_TABLE_OFFSET
                   for address, _ in labels)
    assert result["physical_global_observer_checked"] is False


@pytest.mark.parametrize(
    "label,mutator,expected_reason",
    [
        ("observer.relation_table_pointer",
         lambda image, refs: image.put_u64(refs["observer_pointer"] + memory.RELATION_TABLE_OFFSET, 0),
         "relation_table_pointer_invalid"),
        ("relation_row.owner_pointer",
         lambda image, refs: image.put_u64(RELATION_TABLE + refs["target_slot"] * memory.RELATION_ROW_STRIDE, 0),
         "relation_row_owner_pointer_invalid"),
        ("relation_owner.counters_pointer",
         lambda image, refs: image.put_u64(RELATION_OWNER + memory.RELATION_OWNER_COUNTERS_OFFSET, 0),
         "relation_owner_counters_pointer_invalid"),
        ("target_country.capital_pointer",
         lambda image, refs: image.put_u64(refs["target_pointer"] + memory.COUNTRY_CAPITAL_OFFSET, 0),
         "target_capital_pointer_invalid"),
        ("target_capital.observer_bitset_pointer",
         lambda image, refs: image.put_u64(CAPITAL + memory.CAPITAL_OBSERVER_BITSET_OFFSET, 0),
         "target_observer_bitset_pointer_invalid"),
    ],
)
def test_null_native_pointers_retract_to_unknown(label, mutator, expected_reason):
    image, bindings, refs = _make_image(counter=0, capital_flags=0x10)
    mutator(image, refs)

    result = _run(image, bindings)

    assert result["status"] == "unknown"
    assert result["admitted"] is None
    assert result["reason"] == expected_reason
    assert result["raw_operands"][-1]["native_operand"] == label


@pytest.mark.parametrize("failure_kind", ["short", "raise"])
def test_short_and_failed_rpm_reads_preserve_failed_operand_and_budget(failure_kind: str):
    image, bindings, _ = _make_image(counter=1)
    global_address = MODULE_BASE + memory.SPECIAL_TARGET_SLOT_RVAS[1][1]
    if failure_kind == "short":
        image.short_at.add(global_address)
    else:
        image.error_at.add(global_address)

    result = _run(image, bindings)

    assert result["status"] == "unknown"
    assert result["admitted"] is None
    failed = result["raw_operands"][-1]
    assert failed["status"] == "failed"
    assert failed["native_operand"] == "DAT_14233d8b8"
    assert result["budget"]["calls"] == 2
    assert result["budget"]["bytes_requested"] == 8


def test_read_budget_is_precharged_and_stops_before_over_budget_read(monkeypatch):
    image, bindings, _ = _make_image(counter=1)
    monkeypatch.setattr(memory, "MAX_TOTAL_RPM_BYTES", 4)

    result = _run(image, bindings)

    assert result["status"] == "unknown"
    assert result["admitted"] is None
    assert result["reason"] == "read_budget_exceeded"
    assert result["budget"]["calls"] == 1
    assert result["budget"]["bytes_requested"] == 4
    assert len(image.reads) == 1


def test_binding_scan_identity_and_pointer_aliases_are_rejected():
    image, bindings, refs = _make_image(counter=1)
    bindings["requested"]["FRA"]["fullref_raw_hex"] = "00" * 8
    result = _run(image, bindings)
    assert result["status"] == "unknown"
    assert result["reason"] == "country_binding_fullref_raw_mismatch:FRA"
    assert image.reads == []

    aliased_bindings, _ = _make_bindings(observer_slot=189, target_slot=300,
                                        observer_pointer=COUNTRY_BASE,
                                        target_pointer=COUNTRY_BASE)
    result = memory.read_country_view_admission(image.read, MODULE_BASE,
                                                aliased_bindings, "FRA", "POR")
    assert result["status"] == "unknown"
    assert result["reason"] == "observer_target_pointer_alias"


def test_pointer_overflow_and_out_of_range_bindings_are_unknown():
    image, bindings, _ = _make_image(counter=1)
    result = memory.read_country_view_admission(image.read,
                                                memory.MAX_USER_ADDRESS_EXCLUSIVE,
                                                bindings, "FRA", "POR")
    assert result["status"] == "unknown"
    assert result["reason"] == "module_base_invalid"
    assert image.reads == []

    bindings["count"] = memory.MAX_COUNTRY_SLOTS + 1
    result = _run(image, bindings)
    assert result["status"] == "unknown"
    assert result["reason"] == "country_scan_shape_invalid"
