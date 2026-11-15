"""Fake-memory tests for the bounded native city-count cache leaf.

These tests exercise the leaf and its country-reference re-resolution only.
They do not prove process/session guards, role or visibility admission,
two-pass consistency, cache freshness, native rendering, or a full province
census; those remain parent responsibilities or unresolved evidence.
"""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.country_territory_memory import (
    CITY_COUNT_CACHE_OFFSET,
    FIELD_ID,
    read_fields,
)
from bridge.information import province_state_memory


MODULE_BASE = 0x140000000
DATABASE = 0x500000
TABLE = 0x600000
COUNTRY = 0x200000
OTHER_COUNTRY = 0x210000
SLOT = 0x7A
TAG = "FRA"
FULLREF = 0x0100007A00415246
TABLE_COUNT = 200
DB_GLOBAL = MODULE_BASE + province_state_memory.DATABASE_GLOBAL_RVA
CITY_COUNT_ADDRESS = COUNTRY + CITY_COUNT_CACHE_OFFSET


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=False)


def _i32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


def make_binding(*, country_pointer: int = COUNTRY, fullref: int = FULLREF,
                 slot: int = SLOT, tag: str = TAG) -> dict[str, object]:
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(country_pointer),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "country_fullref_address": hex(country_pointer + 0x20),
        "table_entry_address": hex(TABLE + slot * 8),
        "table_entry_raw_hex": country_pointer.to_bytes(8, "little").hex(),
    }


class FakeMemory:
    def __init__(self, city_count: int = 23, *, canonical_fullref: int = FULLREF,
                 db_country_pointer: int = COUNTRY, fail_labels: set[str] | None = None,
                 short_labels: set[str] | None = None, wrong_type_labels: set[str] | None = None):
        table_bytes = bytearray(TABLE_COUNT * 8)
        table_bytes[SLOT * 8:SLOT * 8 + 8] = db_country_pointer.to_bytes(8, "little")
        self.regions = {
            DB_GLOBAL: DATABASE.to_bytes(8, "little"),
            DATABASE + province_state_memory.DATABASE_TABLE_OFFSET: TABLE.to_bytes(8, "little"),
            DATABASE + province_state_memory.DATABASE_COUNT_OFFSET: _i32(TABLE_COUNT),
            TABLE: bytes(table_bytes),
            db_country_pointer + province_state_memory.COUNTRY_FULLREF_OFFSET:
                canonical_fullref.to_bytes(8, "little"),
            CITY_COUNT_ADDRESS: _i32(city_count),
        }
        self.calls: list[tuple[int, int, str]] = []
        self.fail_labels = set(fail_labels or ())
        self.short_labels = set(short_labels or ())
        self.wrong_type_labels = set(wrong_type_labels or ())

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls.append((address, size, label))
        if label in self.fail_labels:
            raise OSError(f"fixture read failure: {label}")
        if label in self.wrong_type_labels:
            return None  # type: ignore[return-value]
        for start, data in self.regions.items():
            offset = address - start
            if 0 <= offset and offset + size <= len(data):
                result = data[offset:offset + size]
                if label in self.short_labels:
                    return result[:-1]
                return result
        raise OSError(f"fixture unmapped read: {address:#x}+{size:#x} {label}")


def _read(memory: FakeMemory, binding=None, fields=(FIELD_ID,)):
    return read_fields(memory.read, MODULE_BASE,
                       binding if binding is not None else make_binding(), fields)


def _labels(memory: FakeMemory) -> list[str]:
    return [label for _, _, label in memory.calls]


def test_real_fra_fullref_format_resolves_and_projects_zero_count():
    memory = FakeMemory(city_count=0)

    result = _read(memory)[FIELD_ID]

    assert FULLREF.to_bytes(8, "little").hex() == "465241007a000001"
    assert result["status"] == "known"
    assert result["value"] == {"city_count": 0}
    assert result["unit"] == "native_city_count"
    assert result["scale"] == 1
    assert result["partial"] is True
    assert result["complete"] is False
    raw = result["raw_inputs"]
    assert raw["city_count_cache_address"] == hex(CITY_COUNT_ADDRESS)
    assert raw["city_count_cache_raw_hex"] == "00000000"
    assert raw["city_count_cache_i32"] == 0
    assert raw["native_script_multiply_input_i32"] == 0
    assert raw["native_script_multiplier"] == 1000
    assert raw["native_script_multiply_wrapped_i32"] == 0
    resolution = raw["target_evidence"]["country_reference_resolution"]
    assert resolution["status"] == "known"
    assert resolution["value"] == "FRA"
    assert resolution["raw_inputs"]["slot"] == 122
    assert resolution["raw_inputs"]["country_pointer"] == hex(COUNTRY)
    assert len(memory.calls) == 6


def test_maximum_supported_count_records_native_i32_display_multiply():
    memory = FakeMemory(city_count=65535)

    result = _read(memory)[FIELD_ID]

    assert result["status"] == "known"
    assert result["value"] == {"city_count": 65535}
    raw = result["raw_inputs"]
    assert raw["city_count_cache_raw_hex"] == "ffff0000"
    assert raw["native_script_multiply_unwrapped"] == 65_535_000
    assert raw["native_script_multiply_wrapped_i32"] == 65_535_000


@pytest.mark.parametrize("city_count", [-1, 65536])
def test_negative_or_over_limit_cache_is_unknown_with_raw_evidence(city_count):
    memory = FakeMemory(city_count=city_count)

    result = _read(memory)[FIELD_ID]

    assert result["status"] == "unknown"
    assert result["reason"] == "city_count_cache_out_of_supported_range"
    assert "value" not in result
    assert result["raw_inputs"]["city_count_cache_i32"] == city_count
    assert result["raw_inputs"]["city_count_cache_raw_hex"] == _i32(city_count).hex()


def test_callable_reader_is_supported_and_value_contains_no_pointer_or_raw_bytes():
    memory = FakeMemory(city_count=11)
    calls = []

    def callable_reader(address, size, label):
        calls.append((address, size, label))
        return memory.read(address, size, label)

    result = read_fields(callable_reader, MODULE_BASE, make_binding(), (FIELD_ID,))[FIELD_ID]

    assert result["status"] == "known"
    assert result["value"] == {"city_count": 11}
    assert all(not isinstance(value, str) or not value.startswith("0x")
               for value in result["value"].values())
    assert len(calls) == len(memory.calls) == 6


@pytest.mark.parametrize("fields", [
    None,
    [FIELD_ID],
    FIELD_ID,
    (FIELD_ID, FIELD_ID),
    (FIELD_ID, None),
])
def test_bad_field_tuple_or_duplicate_fails_without_reads(fields):
    memory = FakeMemory()

    result = read_fields(memory.read, MODULE_BASE, make_binding(), fields)

    assert result
    assert all(value["status"] == "unknown" for value in result.values())
    assert all("value" not in value for value in result.values())
    assert memory.calls == []


def test_unsupported_field_is_unknown_and_does_not_resolve_country():
    memory = FakeMemory()

    result = _read(memory, fields=("F01.wars",))

    assert result["F01.wars"]["status"] == "unknown"
    assert result["F01.wars"]["reason"] == "unsupported_field"
    assert "value" not in result["F01.wars"]
    assert memory.calls == []


@pytest.mark.parametrize("case", [
    "slot_mismatch", "tag_mismatch", "high_byte_zero", "byte48_seven",
    "pointer_unaligned", "pointer_bool",
])
def test_invalid_binding_components_are_rejected_before_reads(case):
    binding = make_binding()
    if case == "slot_mismatch":
        binding["slot"] = SLOT + 1
    elif case == "tag_mismatch":
        binding["tag"] = "ENG"
    elif case == "high_byte_zero":
        binding = make_binding(fullref=FULLREF & 0x00FFFFFFFFFFFFFF)
    elif case == "byte48_seven":
        special = (FULLREF & ~(0xFF << 48)) | (7 << 48)
        binding = make_binding(fullref=special)
    elif case == "pointer_unaligned":
        binding["country_pointer"] = hex(COUNTRY + 1)
    elif case == "pointer_bool":
        binding["country_pointer"] = True
    memory = FakeMemory()

    result = _read(memory, binding=binding)[FIELD_ID]

    assert result["status"] == "unknown"
    assert "value" not in result
    assert memory.calls == []


def test_epoch_mismatch_against_database_echo_rejects_before_cache_read():
    supplied = (FULLREF & 0x00FFFFFFFFFFFFFF) | (2 << 56)
    memory = FakeMemory(canonical_fullref=FULLREF)

    result = _read(memory, binding=make_binding(fullref=supplied))[FIELD_ID]

    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["reason"].startswith("target_binding_unverified:")
    assert "country_territory.city_count.cache_i32" not in _labels(memory)


def test_database_pointer_mismatch_rejects_before_cache_read():
    memory = FakeMemory(db_country_pointer=OTHER_COUNTRY)

    result = _read(memory, binding=make_binding(country_pointer=COUNTRY))[FIELD_ID]

    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["reason"].startswith("target_binding_unverified:")
    assert "country_territory.city_count.cache_i32" not in _labels(memory)


@pytest.mark.parametrize("failure", ["raise", "short", "wrong_type"])
def test_cache_read_failure_retracts_field_but_retains_identity_evidence(failure):
    kwargs = {
        "fail_labels": {"country_territory.city_count.cache_i32"} if failure == "raise" else None,
        "short_labels": {"country_territory.city_count.cache_i32"} if failure == "short" else None,
        "wrong_type_labels": {"country_territory.city_count.cache_i32"} if failure == "wrong_type" else None,
    }
    memory = FakeMemory(**kwargs)

    result = _read(memory)[FIELD_ID]

    assert result["status"] == "unknown"
    assert "value" not in result
    assert "country_reference_resolution" in result["raw_inputs"]["target_evidence"]
    assert "city_count_cache_raw_hex" not in result["raw_inputs"]
    assert _labels(memory)[-1] == "country_territory.city_count.cache_i32"


def test_non_reader_object_fails_closed_without_native_or_process_fallback():
    result = read_fields(object(), MODULE_BASE, make_binding(), (FIELD_ID,))[FIELD_ID]

    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["reason"].startswith("target_binding_unverified:")
    assert result["raw_inputs"]["country_reference_resolution"]["status"] == "unknown"

