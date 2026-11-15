from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import military_quality_memory as memory


MODULE_BASE = 0x140000000
COUNTRY_POINTER = 0x200000000
MANAGER = 0x200100000
BUCKETS = 0x200110000
ITEM = 0x200120000
ITEM_2 = 0x200121000
DEFINITION = 0x200130000
DEFINITION_2 = 0x200131000
TECHNOLOGY = 0x200140000
VECTOR = 0x200150000


class BoundedReader:
    def __init__(self):
        self.memory: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []

    def put(self, address: int, raw: bytes) -> None:
        self.memory.update({address + index: value for index, value in enumerate(raw)})

    def qword(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(8, "little", signed=False))

    def i32(self, address: int, value: int) -> None:
        self.put(address, (int(value) & 0xFFFFFFFF).to_bytes(4, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        try:
            return bytes(self.memory[address + index] for index in range(size))
        except KeyError as exc:
            raise AssertionError(f"unexpected bounded read: {label} {address:#x} {size}") from exc


def _reader(*, key: bytes = memory.TECHNOLOGY_KEY_BYTES, index: int = 3, value: int = 7,
            cycle: bool = False, bad_guard: bool = False) -> BoundedReader:
    profile = memory._load_profile()
    layout = memory._profile_layout(profile)
    reader = BoundedReader()
    for _name, rva, _end, raw in memory._profile_code_guards(profile):
        guard = bytearray(raw)
        if bad_guard and _name == "military_quality_getter_6df5a0":
            guard[0] ^= 0xFF
        reader.put(MODULE_BASE + rva, bytes(guard))

    reader.qword(MODULE_BASE + layout["singleton_global_rva"], MANAGER)
    reader.i32(MANAGER + layout["manager_bucket_count_offset"], 17)
    reader.qword(MANAGER + layout["manager_buckets_offset"], BUCKETS)
    bucket_index = memory._hash_key(memory.TECHNOLOGY_KEY_BYTES) % 17
    reader.qword(BUCKETS + bucket_index * layout["bucket_entry_stride"], ITEM)
    reader.qword(ITEM + layout["chain_definition_offset"], DEFINITION)
    reader.qword(ITEM + layout["chain_next_offset"], ITEM if cycle else 0)

    # The native lookup uses the short-string storage when capacity < 0x10.
    reader.put(DEFINITION + layout["definition_key_string_offset"], key + b"\0" * 8)
    reader.qword(DEFINITION + layout["definition_key_length_offset"], len(key))
    reader.qword(DEFINITION + layout["definition_key_capacity_offset"], 15)
    reader.i32(DEFINITION + layout["definition_index_offset"], index)

    reader.qword(COUNTRY_POINTER + layout["country_technology_pointer_offset"], TECHNOLOGY)
    reader.qword(TECHNOLOGY + layout["technology_vector_begin_offset"], VECTOR)
    reader.qword(TECHNOLOGY + layout["technology_vector_end_offset"], VECTOR + 16)
    for offset, item in enumerate((1, 2, 3, value)):
        reader.i32(VECTOR + offset * layout["technology_component_width"], item)
    return reader


def test_dynamic_definition_index_non_two_is_read_and_validated() -> None:
    reader = _reader(index=3, value=7)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    assert record["fields"]["military_technology"] == {
        "status": "known",
        "complete": True,
        "value": 7,
        "raw": 7,
        "raw_hex": "07000000",
        "unit": "technology_level",
        "scale": 1,
        "basis": memory.BASIS,
        "period": "current",
        "value_origin": memory.VALUE_ORIGIN,
    }
    lookup = record["observation"]["lookup"]
    assert lookup["lookup"]["key"] == "mil_tech"
    assert lookup["definition_index"] == 3
    assert lookup["vector_count"] == 4
    assert lookup["vector_capacity"] is None
    assert memory.validate_record(record)
    assert sum(size for _address, size, _label in reader.reads) <= memory.READ_BUDGET_BYTES


def test_missing_definition_key_stays_unknown_without_fallback() -> None:
    reader = _reader(key=b"otherkey", index=0, value=99)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "definition_key_not_found"
    assert record["fields"]["military_technology"]["status"] == "unknown"
    assert record["values"] is None
    assert not any(label.endswith("technology.level") for _address, _size, label in reader.reads)


def test_bucket_cycle_is_rejected_with_bounded_chain() -> None:
    reader = _reader(key=b"otherkey", cycle=True)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "bucket_chain_cycle"
    assert len(record["observation"].get("chain", [])) == 1
    assert len(reader.reads) < memory.MAX_CHAIN_STEPS * 4


def test_bad_guard_rejects_before_singleton_or_country_reads() -> None:
    reader = _reader(bad_guard=True)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "runtime_code_guard_failed"
    assert not any("singleton.manager" in label or "country.technology" in label for _address, _size, label in reader.reads)


def test_budget_failure_is_counted_before_failing_reader_call(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _reader()
    class TinyBudget(memory._ReadBudget):
        def __init__(self, _limit: int = memory.READ_BUDGET_BYTES):
            super().__init__(300)

    monkeypatch.setattr(memory, "_ReadBudget", TinyBudget)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "runtime_code_guard_failed"
    assert record["observation"]["read_budget"]["bytes_reserved"] == 242
    assert record["runtime_code_guard"]["bytes_reserved"] == 242


def test_real_validator_rejects_value_lookup_and_guard_tampering() -> None:
    record = memory.read_fields(_reader(), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    value_tampered = deepcopy(record)
    value_tampered["values"]["military_technology"] += 1
    assert not memory.validate_record(value_tampered)

    lookup_tampered = deepcopy(record)
    lookup_tampered["observation"]["lookup"]["definition_index"] = 2
    assert not memory.validate_record(lookup_tampered)

    guard_tampered = deepcopy(record)
    guard_tampered["runtime_code_guard"]["checks"]["military_quality_getter_6df5a0"] = False
    assert not memory.validate_record(guard_tampered)


def test_profile_rejection_does_not_touch_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = BoundedReader()

    def reject(*_args, **_kwargs):
        raise memory.ProfileError("profile rejected")

    monkeypatch.setattr(memory, "_load_profile", reject)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert reader.reads == []


def test_retraction_cannot_validate_as_known() -> None:
    record = memory.read_fields(_reader(), MODULE_BASE, COUNTRY_POINTER)
    retracted = memory.retract_record(record, "cleanup_failed")

    assert retracted["status"] == "unknown"
    assert retracted["fields"]["military_technology"]["status"] == "unknown"
    assert not memory.validate_record(retracted)
