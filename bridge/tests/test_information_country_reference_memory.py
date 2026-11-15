"""Offline tests for the bounded country-manager reference resolver."""
from __future__ import annotations

import pytest

from bridge.information import country_reference_memory as memory


MODULE_BASE = 0x140000000
DATABASE = 0x6200000000
TABLE = 0x6300000000
COUNTRY_BASE = 0x6400000000


class MemoryImage:
    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.short_at: int | None = None
        self.error_at: int | None = None

    def put(self, address: int, raw: bytes) -> None:
        self.bytes.update({address + offset: byte for offset, byte in enumerate(raw)})

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if self.error_at == address:
            raise OSError("synthetic read error")
        result = bytes(self.bytes[address + offset] for offset in range(size))
        if self.short_at == address:
            return result[:-1]
        return result


def fullref(tag: str, slot: int, generation: int = 0) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


def make_image(count: int, entries: dict[int, tuple[str, int, int] | None]) -> MemoryImage:
    """entries map slot to (tag, ref_slot, generation), or None for a null slot."""
    image = MemoryImage()
    image.put_u64(MODULE_BASE + memory.DATABASE_GLOBAL_RVA, DATABASE)
    image.put_u64(DATABASE + memory.DATABASE_TABLE_OFFSET, TABLE)
    image.put_i32(DATABASE + memory.DATABASE_TABLE_COUNT_OFFSET, count)
    for slot in range(count):
        item = entries.get(slot)
        pointer = 0 if item is None else COUNTRY_BASE + slot * 0x100
        image.put_u64(TABLE + slot * 8, pointer)
        if item is not None:
            tag, ref_slot, generation = item
            image.put_u64(pointer + memory.COUNTRY_FULLREF_OFFSET, fullref(tag, ref_slot, generation))
    return image


def test_resolves_targets_above_256_and_keeps_full_reference_and_observer_separate():
    observer = fullref("FRA", 189, generation=0x1234)
    target = fullref("ENG", 300, generation=0x4567)
    image = make_image(310, {189: ("FRA", 189, 0x1234), 300: ("ENG", 300, 0x4567)})

    result = memory.resolve_countries(image.read, MODULE_BASE, ["FRA", "ENG"],
                                      expected_refs={"FRA": observer})

    assert result["count"] == 310
    assert len(result["rows"]) == 310
    assert result["requested"]["FRA"]["slot"] == 189
    assert result["requested"]["FRA"]["fullref"] == hex(observer)
    assert result["requested"]["ENG"]["slot"] == 300
    assert result["requested"]["ENG"]["fullref"] == hex(target)
    assert result["requested"]["ENG"]["country_pointer"] != result["requested"]["FRA"]["country_pointer"]
    assert result["rows"][0]["country_pointer"] is None
    assert result["read_summary"]["bytes_requested"] == sum(size for _, size, _ in image.reads)
    assert max(size for _, size, _ in image.reads) <= 8
    assert result["requested"]["FRA"]["fullref_raw_hex"] == observer.to_bytes(8, "little").hex()


def test_expected_fullref_compares_all_64_bits_including_generation():
    actual = fullref("FRA", 189, generation=0xAAAA)
    image = make_image(190, {189: ("FRA", 189, 0xAAAA)})

    with pytest.raises(memory.CountryReferenceError, match="expected_fullref_mismatch:FRA"):
        memory.resolve_countries(image.read, MODULE_BASE, ["FRA"],
                                 expected_refs={"FRA": actual ^ (1 << 63)})


def test_duplicate_requested_tag_candidates_include_wrong_slot_candidate():
    image = make_image(5, {1: ("ENG", 1, 0), 3: ("ENG", 1, 0)})

    with pytest.raises(memory.CountryReferenceError, match="requested_country_duplicate:ENG"):
        memory.resolve_countries(image.read, MODULE_BASE, ["ENG"])


def test_requested_tag_with_wrong_embedded_slot_is_rejected():
    image = make_image(5, {3: ("ENG", 2, 0)})

    with pytest.raises(memory.CountryReferenceError, match="requested_country_slot_mismatch:ENG"):
        memory.resolve_countries(image.read, MODULE_BASE, ["ENG"])


def test_bad_fullref_tag_and_missing_requested_tag_are_rejected():
    image = make_image(2, {0: ("---", 0, 0)})
    with pytest.raises(memory.CountryReferenceError, match="requested_country_missing:ENG"):
        memory.resolve_countries(image.read, MODULE_BASE, ["ENG"])

    image = make_image(2, {0: ("FRA", 0, 0)})
    with pytest.raises(memory.CountryReferenceError, match="requested_country_missing:ENG"):
        memory.resolve_countries(image.read, MODULE_BASE, ["ENG"])


def test_null_slots_are_preserved_without_inventing_a_country():
    image = make_image(3, {0: None, 2: ("FRA", 2, 0)})

    result = memory.resolve_countries(image.read, MODULE_BASE, ["FRA"])

    assert result["rows"][0]["country_pointer"] is None
    assert result["rows"][0]["fullref"] is None
    assert result["requested"]["FRA"]["slot"] == 2


def test_special_unrelated_native_row_does_not_block_ordinary_country_binding():
    image = make_image(3, {0: ("---", 0, 0), 2: ("FRA", 2, 0x100)})
    result = memory.resolve_countries(image.read, MODULE_BASE, ["FRA"])
    assert result["rows"][0]["tag"] is None
    assert result["rows"][0]["fullref_raw_hex"] == fullref("---", 0).to_bytes(8, "little").hex()
    assert result["requested"]["FRA"]["slot"] == 2


def test_repeated_country_pointer_is_rejected_as_alias():
    image = make_image(2, {0: ("FRA", 0, 0), 1: ("ENG", 1, 0)})
    shared_pointer = COUNTRY_BASE
    image.put_u64(TABLE + 8, shared_pointer)
    image.put_u64(shared_pointer + memory.COUNTRY_FULLREF_OFFSET, fullref("ENG", 1))

    with pytest.raises(memory.CountryReferenceError, match="country_pointer_alias:1"):
        memory.resolve_countries(image.read, MODULE_BASE, ["FRA"])


def test_short_and_failed_reads_are_rejected():
    image = make_image(1, {0: ("FRA", 0, 0)})
    image.short_at = TABLE
    with pytest.raises(memory.CountryReferenceError, match="short_or_invalid_read"):
        memory.resolve_countries(image.read, MODULE_BASE, ["FRA"])

    image = make_image(1, {0: ("FRA", 0, 0)})
    image.error_at = TABLE
    with pytest.raises(memory.CountryReferenceError, match="read_failed"):
        memory.resolve_countries(image.read, MODULE_BASE, ["FRA"])


def test_signed_count_and_slot_limit_are_checked_before_table_walk():
    image = make_image(1, {0: ("FRA", 0, 0)})
    image.put_i32(DATABASE + memory.DATABASE_TABLE_COUNT_OFFSET, -1)
    with pytest.raises(memory.CountryReferenceError, match="country_count_out_of_range"):
        memory.resolve_countries(image.read, MODULE_BASE, ["FRA"])

    image = make_image(1, {0: ("FRA", 0, 0)})
    image.put_i32(DATABASE + memory.DATABASE_TABLE_COUNT_OFFSET, memory.MAX_COUNTRY_SLOTS + 1)
    with pytest.raises(memory.CountryReferenceError, match="country_count_out_of_range"):
        memory.resolve_countries(image.read, MODULE_BASE, ["FRA"])


def test_total_read_budget_is_enforced(monkeypatch):
    image = make_image(1, {0: ("FRA", 0, 0)})
    monkeypatch.setattr(memory, "MAX_TOTAL_READ_BYTES", 32)

    with pytest.raises(memory.CountryReferenceError, match="read_budget_exceeded"):
        memory.resolve_countries(image.read, MODULE_BASE, ["FRA"])


def test_module_pointer_and_table_range_bounds_are_checked():
    image = make_image(1, {0: ("FRA", 0, 0)})
    with pytest.raises(memory.CountryReferenceError, match="module_base_invalid|pointer_arithmetic"):
        memory.resolve_countries(image.read, memory.MAX_USER_ADDRESS_EXCLUSIVE - 8, ["FRA"])

    image = make_image(2, {0: ("FRA", 0, 0)})
    image.put_u64(DATABASE + memory.DATABASE_TABLE_OFFSET, memory.MAX_USER_ADDRESS_EXCLUSIVE - 8)
    with pytest.raises(memory.CountryReferenceError, match="address_range_invalid:country_table"):
        memory.resolve_countries(image.read, MODULE_BASE, ["FRA"])


def test_requested_tags_and_expected_refs_shape_are_strict():
    image = make_image(1, {0: ("FRA", 0, 0)})
    with pytest.raises(memory.CountryReferenceError, match="duplicate_requested_tag:FRA"):
        memory.resolve_countries(image.read, MODULE_BASE, ["FRA", "FRA"])
    with pytest.raises(memory.CountryReferenceError, match="requested_tag_invalid"):
        memory.resolve_countries(image.read, MODULE_BASE, ["Fra"])
    with pytest.raises(memory.CountryReferenceError, match="expected_ref_not_requested"):
        memory.resolve_countries(image.read, MODULE_BASE, ["FRA"], expected_refs={"ENG": fullref("ENG", 0)})

