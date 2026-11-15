from __future__ import annotations

import pytest

from bridge.information.country_ruler_union_memory import (
    COUNTRY_FULLREF_OFFSET,
    DATABASE_GLOBAL_RVA,
    DATABASE_TABLE_COUNT_OFFSET,
    DATABASE_TABLE_OFFSET,
    OWNER_ENTRIES_OFFSET,
    OWNER_ENTRY_COUNT_OFFSET,
    OWNER_ENTRY_STRIDE,
    RELATION_OBJECT_TYPE_OFFSET,
    RELATION_ROW_STRIDE,
    RELATION_TYPE_FLAG_OFFSET,
    TARGET_PERSONAL_UNION_REF_OFFSET,
    TARGET_RELATION_TABLE_OFFSET,
    read_ruler_union_gate,
)


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


def _fullref(tag: str, slot: int, *, discriminator: int = 0xA7) -> int:
    return ((discriminator & 0xFF) << 56) | (slot << 32) | int.from_bytes(
        tag.encode("ascii"), "little")


class FakeLimiter:
    def __init__(self) -> None:
        self.memory: dict[int, int] = {}
        self.short_labels: set[str] = set()
        self.fail_labels: set[str] = set()
        self.calls: list[tuple[int, int, str]] = []

    def put(self, address: int, raw: bytes) -> None:
        for offset, value in enumerate(raw):
            self.memory[address + offset] = value

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls.append((address, size, label))
        if label in self.fail_labels:
            raise OSError("fixture read failure")
        raw = bytes(self.memory[address + offset] for offset in range(size)
                    if address + offset in self.memory)
        if len(raw) != size:
            raise OSError("fixture address is unmapped")
        if label in self.short_labels:
            return raw[:-1]
        return raw


def _fixture(*, discriminator: int = 0xA7, owner_count: int = 1,
             entry_slots: tuple[int, ...] | None = None,
             relation_object: int = 0x900000,
             type_pointer: int = 0xA00000,
             type_flag: int = 0,
             database_related_ref: int | None = None) -> tuple[FakeLimiter, int, dict[str, object], dict[str, int]]:
    reader = FakeLimiter()
    base = 0x140000000
    selected_country = 0x200000
    database = 0x300000
    country_table = 0x400000
    related_country = 0x500000
    relation_table = 0x600000
    owner = 0x700000
    entries = 0x800000
    relation = 0x900000
    relation_type = 0xA00000
    selected_slot = 189
    related_slot = 46
    selected_ref = _fullref("POR", selected_slot)
    related_ref = _fullref("ENG", related_slot, discriminator=discriminator)

    reader.put(selected_country + COUNTRY_FULLREF_OFFSET, _u64(selected_ref))
    reader.put(selected_country + TARGET_PERSONAL_UNION_REF_OFFSET, _u64(related_ref))
    reader.put(base + DATABASE_GLOBAL_RVA, _u64(database))
    reader.put(database + DATABASE_TABLE_OFFSET, _u64(country_table))
    reader.put(database + DATABASE_TABLE_COUNT_OFFSET, _i32(200))
    reader.put(country_table + related_slot * 8, _u64(related_country))
    reader.put(related_country + COUNTRY_FULLREF_OFFSET,
               _u64(database_related_ref if database_related_ref is not None else related_ref))

    reader.put(selected_country + TARGET_RELATION_TABLE_OFFSET, _u64(relation_table))
    row = bytearray(0x18)
    row[0:8] = _u64(owner)
    row[0x10:0x18] = _u64(related_ref)
    reader.put(relation_table + related_slot * RELATION_ROW_STRIDE, bytes(row))

    reader.put(owner + OWNER_ENTRIES_OFFSET, _u64(entries))
    reader.put(owner + OWNER_ENTRY_COUNT_OFFSET, _i32(owner_count))
    if entry_slots is None:
        entry_slots = (related_slot,) if owner_count > 0 else ()
    if owner_count > 0 and len(entry_slots) <= 4096:
        array = bytearray(owner_count * OWNER_ENTRY_STRIDE)
        for index, slot in enumerate(entry_slots[:owner_count]):
            start = index * OWNER_ENTRY_STRIDE
            array[start:start + 4] = _i32(slot)
            array[start + 8:start + 16] = _u64(
                relation_object if slot == related_slot else 0x910000)
        reader.put(entries, bytes(array))
    if relation_object:
        reader.put(relation + RELATION_OBJECT_TYPE_OFFSET, _u64(type_pointer))
    if type_pointer:
        reader.put(relation_type + RELATION_TYPE_FLAG_OFFSET, bytes([type_flag]))

    binding: dict[str, object] = {
        "tag": "POR",
        "slot": selected_slot,
        "fullref": hex(selected_ref),
        "country_pointer": hex(selected_country),
        "fullref_raw_hex": selected_ref.to_bytes(8, "little").hex(),
    }
    addresses = {
        "selected_country": selected_country,
        "related_country": related_country,
        "related_ref": related_ref,
        "related_slot": related_slot,
        "owner": owner,
        "entries": entries,
        "relation": relation,
        "relation_type": relation_type,
    }
    return reader, base, binding, addresses


@pytest.mark.parametrize(
    ("fixture_options", "expected_reason"),
    [
        ({"discriminator": 0}, "related_discriminator_zero"),
        ({"owner_count": 0}, "owner_entry_count_zero"),
        ({"entry_slots": (47,)}, "matching_owner_entry_absent"),
        ({"relation_object": 0}, "relation_object_null"),
        ({"type_pointer": 0}, "relation_type_pointer_null"),
        ({"type_flag": 0}, "relation_type_flag_zero"),
    ],
)
def test_known_false_outcomes_are_scoped_to_this_writer_gate(
    fixture_options: dict[str, object], expected_reason: str,
) -> None:
    reader, base, binding, _ = _fixture(**fixture_options)

    result = read_ruler_union_gate(reader, base, binding)

    assert result["status"] == "known"
    assert result["active"] is False
    assert result["reason"] == expected_reason
    assert "related_country" not in result
    assert "DOES_NOT_ENUMERATE_ALL_SUBJECT_OR_UNION_RELATIONSHIPS" in result["scope"]
    assert result["raw_inputs"]["reads"]


def test_any_nonzero_relation_type_byte_returns_true_and_exact_related_binding() -> None:
    reader, base, binding, addresses = _fixture(type_flag=0x80)

    result = read_ruler_union_gate(reader, base, binding)

    assert result["status"] == "known"
    assert result["active"] is True
    assert result["reason"] == "relation_type_flag_nonzero"
    assert result["related_country"] == {
        "tag": "ENG",
        "slot": addresses["related_slot"],
        "fullref": hex(addresses["related_ref"]),
    }
    assert result["raw_inputs"]["relation_type_flag_raw_hex"] == "80"
    assert result["raw_inputs"]["resolved_related_country_fullref"] == hex(
        addresses["related_ref"])


def test_related_database_fullref_must_match_the_selected_country_reference() -> None:
    reader, base, binding, addresses = _fixture(
        type_flag=1,
        database_related_ref=_fullref("ENG", addresses_slot := 47),
    )

    result = read_ruler_union_gate(reader, base, binding)

    assert result["status"] == "unknown"
    assert "active" not in result
    assert result["reason"] == "related_country_fullref_mismatch"
    assert result["raw_inputs"]["related_country_slot"] == 46
    assert addresses_slot != result["raw_inputs"]["related_country_slot"]


def test_duplicate_matching_owner_entries_are_unknown_not_guessed() -> None:
    reader, base, binding, _ = _fixture(entry_slots=(46, 46), owner_count=2)

    result = read_ruler_union_gate(reader, base, binding)

    assert result["status"] == "unknown"
    assert "active" not in result
    assert result["reason"] == "duplicate_matching_owner_entries"
    assert result["raw_inputs"]["matching_owner_entry_indices"] == [0, 1]


@pytest.mark.parametrize("count", [-1, 4097])
def test_invalid_owner_entry_count_is_unknown_before_array_read(count: int) -> None:
    reader, base, binding, _ = _fixture(owner_count=count)

    result = read_ruler_union_gate(reader, base, binding)

    assert result["status"] == "unknown"
    assert result["reason"] == "owner_entry_count_out_of_range"
    assert "active" not in result
    assert not any(label == "ruler_union.owner_entries"
                   for _, _, label in reader.calls)


def test_short_read_preserves_failure_and_never_returns_active_false() -> None:
    reader, base, binding, _ = _fixture(type_flag=1)
    reader.short_labels.add("ruler_union.relation_type_flag")

    result = read_ruler_union_gate(reader, base, binding)

    assert result["status"] == "unknown"
    assert "active" not in result
    assert result["reason"].startswith("short_read:ruler_union.relation_type_flag")
    assert result["raw_inputs"]["reads"][-1]["status"] == "failed"


def test_target_binding_is_checked_against_fullref_and_memory() -> None:
    reader, base, binding, addresses = _fixture()
    bad_binding = dict(binding)
    bad_binding["slot"] = 188

    invalid = read_ruler_union_gate(reader, base, bad_binding)
    assert invalid["status"] == "unknown"
    assert invalid["reason"] == "target_binding_fullref_slot_mismatch"
    assert invalid["raw_inputs"]["read_calls"] == 0

    reader.put(addresses["selected_country"] + COUNTRY_FULLREF_OFFSET,
               _u64(_fullref("POR", 188)))
    mismatch = read_ruler_union_gate(reader, base, binding)
    assert mismatch["status"] == "unknown"
    assert mismatch["reason"] == "target_binding_fullref_memory_mismatch"
    assert "active" not in mismatch


def test_bad_pointer_and_reader_failure_remain_unknown_with_raw_diagnostics() -> None:
    reader, base, binding, _ = _fixture(type_flag=1)
    reader.put(binding_pointer := int(binding["country_pointer"], 0) + TARGET_RELATION_TABLE_OFFSET,
               _u64(0xFFFF))

    bad_pointer = read_ruler_union_gate(reader, base, binding)
    assert bad_pointer["status"] == "unknown"
    assert "active" not in bad_pointer
    assert bad_pointer["reason"] == "relation_table_invalid"

    reader, base, binding, _ = _fixture(type_flag=1)
    reader.fail_labels.add("ruler_union.database_global")
    failed = read_ruler_union_gate(reader, base, binding)
    assert failed["status"] == "unknown"
    assert "active" not in failed
    assert failed["reason"].startswith("read_failed:ruler_union.database_global")
    assert failed["raw_inputs"]["reads"][-1]["status"] == "failed"
