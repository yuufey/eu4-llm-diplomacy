from __future__ import annotations

import struct

import pytest

from bridge.information import province_development_memory as development


BASE = 0x140000000
RECORD = 0x100000000
DATABASE = 0x180000000
TABLE = 0x190000000
COUNTRY = 0x1A0000000
TRIBAL = 0x1B0000000
PROVINCE_ID = 183
SLOT = 3
I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1


class FakeMemory:
    def __init__(self):
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.fail_labels: set[str] = set()
        self.short_labels: set[str] = set()

    def write(self, address: int, value: bytes) -> None:
        for index, byte in enumerate(value):
            self.data[address + index] = byte

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label in self.fail_labels:
            raise OSError(f"fixture_failure:{label}")
        try:
            result = bytes(self.data[address + index] for index in range(size))
        except KeyError as exc:
            raise OSError(f"fixture_unmapped:{label}") from exc
        if label in self.short_labels:
            return result[:-1]
        return result


class CappedMemory:
    """A stand-in for a parent limiter; the leaf must use this same reader."""

    def __init__(self, memory: FakeMemory, *, max_calls: int, max_bytes: int):
        self.memory = memory
        self.max_calls = max_calls
        self.max_bytes = max_bytes
        self.calls = 0
        self.bytes = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if self.calls + 1 > self.max_calls or self.bytes + size > self.max_bytes:
            raise RuntimeError("parent_budget_exceeded")
        self.calls += 1
        self.bytes += size
        return self.memory.read(address, size, label)


def _fullref(slot: int = SLOT, tag: bytes = b"FRA\0", high: int = 1,
             generation: int = 0) -> int:
    assert len(tag) == 4
    return ((high & 0xFF) << 56) | ((generation & 0xFF) << 48) | (slot << 32) | int.from_bytes(tag, "little")


def binding(province_id: int = PROVINCE_ID, record: int = RECORD) -> dict:
    return {
        "province_id": province_id,
        "record_id": province_id,
        "record_pointer": hex(record),
        "id_address": hex(record + 0x20),
        "id_raw_hex": struct.pack("<i", province_id).hex(),
    }


def setup(*, bases=(12000, 8000, 5000), tribal=0, capital_id=PROVINCE_ID,
          bonuses=(0, 0, 0), owner_ref=None, country_ref=None,
          table_pointer=TABLE, count=8) -> FakeMemory:
    memory = FakeMemory()
    owner_ref = _fullref() if owner_ref is None else owner_ref
    country_ref = owner_ref if country_ref is None else country_ref
    memory.write(RECORD + 0x20, struct.pack("<i", PROVINCE_ID))
    memory.write(RECORD + development.OWNER_FULLREF_OFFSET, struct.pack("<Q", owner_ref))
    for value, offset in zip(
            bases, (development.TAX_BASE_OFFSET,
                    development.PRODUCTION_BASE_OFFSET,
                    development.MANPOWER_BASE_OFFSET)):
        memory.write(RECORD + offset, struct.pack("<i", value))

    memory.write(BASE + 0x233D8B0, struct.pack("<Q", DATABASE))
    memory.write(DATABASE + 0x118, struct.pack("<Q", table_pointer))
    memory.write(DATABASE + 0x124, struct.pack("<i", count))
    if table_pointer == TABLE and count > SLOT:
        memory.write(TABLE + SLOT * 8, struct.pack("<Q", COUNTRY))
    memory.write(COUNTRY + 0x20, struct.pack("<Q", country_ref))
    memory.write(COUNTRY + development.COUNTRY_TRIBAL_POINTER_OFFSET,
                 struct.pack("<Q", tribal))
    if tribal:
        memory.write(COUNTRY + development.COUNTRY_PROVINCE_ID_OFFSET,
                     struct.pack("<i", capital_id))
        for value, offset in zip(
                bonuses, (development.TRIBAL_TAX_OFFSET,
                          development.TRIBAL_PRODUCTION_OFFSET,
                          development.TRIBAL_MANPOWER_OFFSET)):
            memory.write(tribal + offset, struct.pack("<i", value))
    return memory


def read(memory, *, fields=(development.FIELD_ID,), province_binding=None):
    return development.read_fields(
        memory, BASE,
        binding() if province_binding is None else province_binding,
        list(fields),
    )


def only_field(result):
    return result[development.FIELD_ID]


def test_null_tribal_pointer_is_valid_zero_bonus_and_short_circuits():
    memory = setup(bases=(12345, -2345, 1000), tribal=0)

    result = only_field(read(memory))

    assert result["status"] == "known"
    assert result["value"] == 11000
    assert result["scale"] == 1000
    assert result["partial"] is True and result["complete"] is False
    assert result["raw_inputs"]["bonus_gate"] == "null_tribal_pointer"
    assert result["raw_inputs"]["display_integer"] == 11
    labels = [label for _address, _size, label in memory.reads]
    assert "province_development.owner.province_id" not in labels
    assert not any(label.startswith("province_development.bonus.") for label in labels)
    assert "country_pointer" in repr(result["raw_inputs"])
    assert isinstance(result["value"], int)


def test_nonmatching_owner_province_reads_capital_but_not_bonus_values():
    memory = setup(tribal=TRIBAL, capital_id=184, bonuses=(9000, 8000, 7000))

    result = only_field(read(memory))

    assert result["status"] == "known"
    assert result["value"] == 25000
    assert result["raw_inputs"]["bonus_gate"] == "owner_province_id_mismatch"
    labels = [label for _address, _size, label in memory.reads]
    assert "province_development.owner.province_id" in labels
    assert not any(label.startswith("province_development.bonus.") for label in labels)


@pytest.mark.parametrize(
    ("bonuses", "expected_components", "expected_total", "expected_display"),
    [
        ((1999, -1999, -999), (13000, 7000, 5000), 25000, 25),
        ((-1999, 999, -1), (11000, 8000, 5000), 24000, 24),
        ((-999, 1999, -2001), (12000, 9000, 3000), 24000, 24),
    ],
)
def test_matching_owner_applies_signed_bonus_truncation_toward_zero(
        bonuses, expected_components, expected_total, expected_display):
    memory = setup(tribal=TRIBAL, bonuses=bonuses)

    result = only_field(read(memory))

    assert result["status"] == "known"
    assert result["value"] == expected_total
    assert result["raw_inputs"]["component_raw_values"] == {
        "tax": expected_components[0],
        "production": expected_components[1],
        "manpower": expected_components[2],
    }
    assert result["raw_inputs"]["display_integer"] == expected_display
    components = result["raw_inputs"]["components"]
    for name, raw in zip(("tax", "production", "manpower"), bonuses):
        quotient = raw // 1000 if raw >= 0 else -((-raw) // 1000)
        assert components[name]["bonus_raw"] == raw
        assert components[name]["bonus_truncated_quotient"] == quotient
        assert components[name]["bonus_value"] == quotient * 1000
        assert components[name]["bonus_read"] is True


def test_i32_component_and_total_addition_wrap_like_native_signed_width():
    memory = setup(
        bases=(I32_MAX, I32_MAX, I32_MAX),
        tribal=TRIBAL,
        bonuses=(1000, 0, 0),
    )

    result = only_field(read(memory))

    assert result["status"] == "known"
    assert result["raw_inputs"]["component_raw_values"] == {
        "tax": -2147482649,
        "production": I32_MAX,
        "manpower": I32_MAX,
    }
    assert result["value"] == -2147482651
    assert result["raw_inputs"]["display_integer"] == -2147482


def test_negative_total_display_division_truncates_toward_zero():
    memory = setup(bases=(-1999, -1, 0))

    result = only_field(read(memory))

    assert result["value"] == -2000
    assert result["raw_inputs"]["display_integer"] == -2
    assert development._trunc_div_1000(-1999) == -1


def test_reader_object_and_callable_are_supported_and_keep_parent_budget():
    memory = setup(tribal=TRIBAL, bonuses=(1000, 2000, 3000))
    capped = CappedMemory(memory, max_calls=32, max_bytes=256)

    result = only_field(read(capped))

    assert result["status"] == "known"
    assert capped.calls == 14
    assert capped.bytes == 8 + 8 + 8 + 4 + 8 + 8 + 12 + 8 + 4 + 12
    assert len(memory.reads) == capped.calls

    callable_memory = setup()
    field = development.read_fields(
        callable_memory.read, BASE, binding(), [development.FIELD_ID])
    assert only_field(field)["status"] == "known"


def test_exhausted_parent_budget_fails_closed_without_restarting_reads():
    memory = setup()
    capped = CappedMemory(memory, max_calls=1, max_bytes=8)

    result = only_field(read(capped))

    assert result["status"] == "unknown"
    assert "value" not in result
    assert capped.calls == 1
    assert len(memory.reads) == 1
    assert memory.reads[0][2] == "province_development.owner_fullref"


@pytest.mark.parametrize(
    "owner_ref",
    [
        _fullref(high=0),
        _fullref(slot=9),
        _fullref(generation=1),
    ],
)
def test_invalid_or_stale_owner_fullref_fails_closed(owner_ref):
    canonical = _fullref() if owner_ref == _fullref(generation=1) else owner_ref
    memory = setup(owner_ref=owner_ref, country_ref=canonical)

    result = only_field(read(memory))

    assert result["status"] == "unknown"
    assert "value" not in result


def test_bad_country_table_and_country_pointer_fail_closed():
    bad_table = setup(table_pointer=TABLE + 1)
    table_result = only_field(read(bad_table))
    assert table_result["status"] == "unknown"
    assert "value" not in table_result

    bad_country = setup()
    bad_country.write(TABLE + SLOT * 8, struct.pack("<Q", 0x55))
    country_result = only_field(read(bad_country))
    assert country_result["status"] == "unknown"
    assert "value" not in country_result


@pytest.mark.parametrize(
    "bad_binding",
    [
        binding(0),
        binding(65536),
        {**binding(), "province_id": True, "record_id": True},
        {**binding(), "record_id": PROVINCE_ID + 1},
        {**binding(), "id_raw_hex": struct.pack("<i", 184).hex()},
        {**binding(), "id_address": hex(RECORD + 0x21)},
        {**binding(), "record_pointer": hex(RECORD + 1)},
    ],
)
def test_invalid_binding_fails_with_zero_memory_reads(bad_binding):
    memory = setup()

    result = only_field(read(memory, province_binding=bad_binding))

    assert result["status"] == "unknown"
    assert "value" not in result
    assert memory.reads == []


def test_unsupported_field_is_unknown_without_reading_any_memory():
    memory = setup()

    result = read(memory, fields=("G02.owner",))

    assert result == {"G02.owner": {"status": "unknown", "reason": "unsupported_field",
                                     "basis": development._BASIS, "scale": 1000,
                                     "period": "current", "partial": True,
                                     "complete": False, "raw_inputs": {}}}
    assert memory.reads == []


@pytest.mark.parametrize(
    ("label", "mode"),
    [
        ("province_development.owner_fullref", "raise"),
        ("province_state.development_owner.database_global", "short"),
        ("province_development.base.tax[183]", "raise"),
        ("province_development.owner.tribal_pointer", "short"),
        ("province_development.owner.province_id", "raise"),
        ("province_development.bonus.production[183]", "short"),
    ],
)
def test_missing_short_or_failed_required_reads_are_unknown(label, mode):
    memory = setup(tribal=TRIBAL, bonuses=(1000, 2000, 3000))
    (memory.fail_labels if mode == "raise" else memory.short_labels).add(label)

    result = only_field(read(memory))

    assert result["status"] == "unknown"
    assert "value" not in result


def test_invalid_tribal_pointer_is_unknown_not_zero_bonus():
    memory = setup(tribal=0x55)

    result = only_field(read(memory))

    assert result["status"] == "unknown"
    assert "value" not in result
    labels = [label for _address, _size, label in memory.reads]
    assert "province_development.owner.province_id" not in labels


def test_duplicate_or_invalid_field_selector_fails_closed():
    memory = setup()

    duplicate = development.read_fields(
        memory, BASE, binding(), [development.FIELD_ID, development.FIELD_ID])
    invalid = development.read_fields(memory, BASE, binding(), "G02.development")

    assert only_field(duplicate)["status"] == "unknown"
    assert "value" not in only_field(duplicate)
    assert only_field(invalid)["status"] == "unknown"
    assert memory.reads == []

